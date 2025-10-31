from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3, jwt, bcrypt
from typing import List, Optional

# ----------------------#
# BASIC SETUP
# ----------------------#
app = FastAPI(title="SlotSwapper API")
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
auth_scheme = HTTPBearer()

# Allowed event statuses
# Note: In SQLite, we enforce this logic in the application layer.
EVENT_STATUSES = ["BUSY", "SWAPPABLE", "SWAP_PENDING"]
SWAP_REQUEST_STATUSES = ["PENDING", "ACCEPTED", "REJECTED"]


# Allow frontend to access backend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------#
# DATABASE SETUP
# ----------------------#
conn = sqlite3.connect("database.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'BUSY', -- BUSY, SWAPPABLE, SWAP_PENDING
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS swap_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requesting_user_id INTEGER NOT NULL,
    offered_slot_id INTEGER NOT NULL, -- The slot the requesting user is giving up
    desired_slot_id INTEGER NOT NULL, -- The slot the requesting user wants
    status TEXT DEFAULT 'PENDING',    -- PENDING, ACCEPTED, REJECTED
    timestamp TEXT,
    FOREIGN KEY (requesting_user_id) REFERENCES users(id),
    FOREIGN KEY (offered_slot_id) REFERENCES events(id),
    FOREIGN KEY (desired_slot_id) REFERENCES events(id)
)''')

conn.commit()

# ----------------------#
# MODELS
# ----------------------#
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class EventCreate(BaseModel):
    title: str
    start_time: str
    end_time: str

class EventStatusUpdate(BaseModel):
    # Only allow BUSY or SWAPPABLE for direct user setting
    status: str
    
    def model_post_init(self, context) -> None:
        if self.status not in ["BUSY", "SWAPPABLE"]:
            raise ValueError("Status must be 'BUSY' or 'SWAPPABLE'")
            
class SwapRequestCreate(BaseModel):
    offered_slot_id: int
    desired_slot_id: int
    
class SwapResponse(BaseModel):
    accept: bool
    
# ----------------------#
# DEPENDENCY FUNCTIONS
# ----------------------#

def create_token(data: dict):
    """Creates a JWT token valid for 5 hours."""
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(hours=5), **data},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    """
    Dependency that extracts and verifies the token from the Authorization header.
    Raises 401 on failure or expiry.
    Returns the user's ID.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
# Helper to package event data
def package_event(row):
    return {
        "id": row[0], 
        "title": row[1], 
        "start_time": row[2], 
        "end_time": row[3], 
        "status": row[4],
        "user_id": row[5],
    }

# ----------------------#
# AUTH ROUTES
# ----------------------#
@app.post("/signup")
def signup(user: UserCreate):
    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (user.name, user.email, hashed_pw)
        )
        conn.commit()
        return {"message": "User registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")

@app.post("/login")
def login(user: UserLogin):
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    db_user = cursor.fetchone()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    stored_hash = db_user[3]
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_token({"user_id": db_user[0], "email": db_user[2]})
    return {"access_token": token, "token_type": "bearer"}

# ----------------------#
# EVENT ROUTES
# ----------------------#

@app.post("/api/events")
def create_event(event: EventCreate, user_id: int = Depends(get_current_user)):
    """Creates a new event for the authenticated user."""
    cursor.execute(
        "INSERT INTO events (title, start_time, end_time, user_id) VALUES (?, ?, ?, ?)",
        (event.title, event.start_time, event.end_time, user_id)
    )
    conn.commit()
    return {"message": "Event created successfully"}

@app.get("/api/events")
def get_user_events(user_id: int = Depends(get_current_user)):
    """Retrieves all events owned by the current user."""
    cursor.execute(
        "SELECT id, title, start_time, end_time, status, user_id FROM events WHERE user_id = ?", 
        (user_id,)
    )
    rows = cursor.fetchall()
    events = [package_event(r) for r in rows]
    return {"events": events}

@app.patch("/api/events/{event_id}/status")
def update_event_status(
    event_id: int, 
    update: EventStatusUpdate, 
    user_id: int = Depends(get_current_user)
):
    """Updates an event's status to BUSY or SWAPPABLE."""
    new_status = update.status
    
    # Ensure the event belongs to the user and is not currently pending a swap
    cursor.execute(
        "SELECT status FROM events WHERE id = ? AND user_id = ?", 
        (event_id, user_id)
    )
    event_row = cursor.fetchone()
    if not event_row:
        raise HTTPException(status_code=404, detail="Event not found or not owned by user.")
        
    current_status = event_row[0]
    if current_status == 'SWAP_PENDING' and new_status == 'BUSY':
         raise HTTPException(status_code=400, detail="Cannot change status of a slot currently pending a swap.")
    
    cursor.execute(
        "UPDATE events SET status = ? WHERE id = ? AND user_id = ?",
        (new_status, event_id, user_id)
    )
    conn.commit()

    return {"message": f"Event {event_id} status updated to {new_status}"}

# ----------------------#
# SWAP LOGIC ROUTES (Core Challenge)
# ----------------------#

@app.get("/api/swappable-slots")
def get_swappable_slots(user_id: int = Depends(get_current_user)):
    """Returns all slots marked 'SWAPPABLE' by *other* users."""
    cursor.execute(
        "SELECT id, title, start_time, end_time, status, user_id FROM events WHERE status = 'SWAPPABLE' AND user_id != ?", 
        (user_id,)
    )
    rows = cursor.fetchall()
    slots = [package_event(r) for r in rows]
    return {"swappable_slots": slots}

@app.post("/api/swap-request", status_code=status.HTTP_201_CREATED)
def create_swap_request(
    request: SwapRequestCreate, 
    requesting_user_id: int = Depends(get_current_user)
):
    """Initiates a swap request and changes slot statuses to SWAP_PENDING."""
    offered_id = request.offered_slot_id
    desired_id = request.desired_slot_id
    
    # 1. Verify Offered Slot (Must belong to requesting user and be SWAPPABLE)
    cursor.execute(
        "SELECT user_id, status FROM events WHERE id = ?", (offered_id,)
    )
    offered_slot = cursor.fetchone()
    if not offered_slot or offered_slot[0] != requesting_user_id or offered_slot[1] != 'SWAPPABLE':
        raise HTTPException(status_code=400, detail="Offered slot is invalid or not SWAPPABLE.")

    # 2. Verify Desired Slot (Must belong to another user and be SWAPPABLE)
    cursor.execute(
        "SELECT user_id, status FROM events WHERE id = ?", (desired_id,)
    )
    desired_slot = cursor.fetchone()
    desired_slot_owner_id = desired_slot[0] if desired_slot else None
    
    if not desired_slot or desired_slot_owner_id == requesting_user_id or desired_slot[1] != 'SWAPPABLE':
        raise HTTPException(status_code=400, detail="Desired slot is invalid or not SWAPPABLE.")

    # 3. Create Swap Request
    try:
        cursor.execute(
            """INSERT INTO swap_requests (requesting_user_id, offered_slot_id, desired_slot_id, timestamp) 
               VALUES (?, ?, ?, ?)""",
            (requesting_user_id, offered_id, desired_id, datetime.now().isoformat())
        )
        request_id = cursor.lastrowid
        
        # 4. Update both slot statuses to SWAP_PENDING
        cursor.execute("UPDATE events SET status = 'SWAP_PENDING' WHERE id IN (?, ?)", (offered_id, desired_id))
        conn.commit()
        
        return {"message": "Swap request created successfully", "request_id": request_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create request: {str(e)}")


@app.post("/api/swap-response/{request_id}")
def respond_to_swap_request(
    request_id: int, 
    response: SwapResponse, 
    user_id: int = Depends(get_current_user)
):
    """Allows a user to Accept/Reject a swap request where they own the DESIRED slot."""

    # 1. Get request details
    cursor.execute(
        """SELECT offered_slot_id, desired_slot_id, requesting_user_id, status FROM swap_requests WHERE id = ?""", 
        (request_id,)
    )
    swap_request = cursor.fetchone()

    if not swap_request or swap_request[3] != 'PENDING':
        raise HTTPException(status_code=404, detail="Swap request not found or already processed.")
        
    offered_id, desired_id, requester_id = swap_request[0], swap_request[1], swap_request[2]

    # 2. Verify the responding user owns the desired slot
    cursor.execute("SELECT user_id FROM events WHERE id = ?", (desired_id,))
    desired_slot_owner = cursor.fetchone()
    
    if not desired_slot_owner or desired_slot_owner[0] != user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to respond to this request.")

    # Start transaction
    try:
        if response.accept:
            # --- ACCEPTANCE LOGIC ---
            
            # 3. Swap the user_id's (the core transaction)
            # Find the user_id of the offered slot owner (the requester)
            # (We already know the desired slot owner is the current user_id)
            
            # Set desired slot (owned by 'user_id') to requester_id
            cursor.execute("UPDATE events SET user_id = ?, status = 'BUSY' WHERE id = ?", (requester_id, desired_id))
            
            # Set offered slot (owned by 'requester_id') to current user_id
            cursor.execute("UPDATE events SET user_id = ?, status = 'BUSY' WHERE id = ?", (user_id, offered_id))
            
            # 4. Mark request as ACCEPTED
            cursor.execute("UPDATE swap_requests SET status = 'ACCEPTED' WHERE id = ?", (request_id,))
            conn.commit()
            return {"message": "Swap accepted! Calendars updated."}
        
        else:
            # --- REJECTION LOGIC ---
            
            # 3. Set both slots back to SWAPPABLE
            cursor.execute("UPDATE events SET status = 'SWAPPABLE' WHERE id IN (?, ?)", (offered_id, desired_id))
            
            # 4. Mark request as REJECTED
            cursor.execute("UPDATE swap_requests SET status = 'REJECTED' WHERE id = ?", (request_id,))
            conn.commit()
            return {"message": "Swap rejected. Slots returned to SWAPPABLE status."}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Transaction failed: {str(e)}")
        

@app.get("/api/swap-requests/incoming")
def get_incoming_requests(user_id: int = Depends(get_current_user)):
    """Returns requests waiting for the current user's approval."""
    
    # Find all PENDING requests where the desired slot's owner is the current user.
    cursor.execute(
        """
        SELECT sr.id, e_offered.title, e_offered.start_time, e_offered.end_time, u_requester.name 
        FROM swap_requests sr
        JOIN events e_desired ON sr.desired_slot_id = e_desired.id
        JOIN events e_offered ON sr.offered_slot_id = e_offered.id
        JOIN users u_requester ON sr.requesting_user_id = u_requester.id
        WHERE e_desired.user_id = ? AND sr.status = 'PENDING'
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    
    requests = [{
        "request_id": r[0],
        "offering_slot_title": r[1],
        "offering_slot_time": f"{r[2]} to {r[3]}",
        "requester_name": r[4],
    } for r in rows]
    
    return {"incoming_requests": requests}


# ----------------------#
# ROOT ENDPOINT
# ----------------------#
@app.get("/")
def home():
    return {"message": "✅ SlotSwapper API is running successfully!"}