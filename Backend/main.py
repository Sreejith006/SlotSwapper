from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt

# ================= CONFIG =================
SECRET_KEY = "supersecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="SlotSwapper Backend")

# Allow your frontend to access this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["http://127.0.0.1:5500"] if you're strict
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= IN-MEMORY DB =================
users_db = {}  # email -> {id, name, email, password}
events_db = []  # list of events

# ================= MODELS =================
class SignupModel(BaseModel):
    name: str
    email: str
    password: str

class EventCreate(BaseModel):
    title: str
    start_time: datetime
    end_time: datetime

class Event(BaseModel):
    id: int
    user_id: str
    title: str
    start_time: datetime
    end_time: datetime
    status: str = "BUSY"

class StatusUpdate(BaseModel):
    status: str

# ================= JWT UTILS =================
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Dependency
def get_current_user(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")
    token = auth_header.split(" ")[1]
    user_id = verify_token(token)
    user = next((u for u in users_db.values() if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ================= ROUTES =================

@app.post("/signup")
def signup(user: SignupModel):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    user_id = f"user_{len(users_db)+1}"
    users_db[user.email] = {
        "id": user_id,
        "name": user.name,
        "email": user.email,
        "password": user.password,  # Plaintext for demo
    }
    return {"message": "Signup successful"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"user_id": user["id"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/events")
def get_user_events(current_user: dict = Depends(get_current_user)):
    user_events = [e for e in events_db if e.user_id == current_user["id"]]
    return {"events": user_events}

@app.post("/events")
def create_event(event: EventCreate, current_user: dict = Depends(get_current_user)):
    new_event = Event(
        id=len(events_db) + 1,
        user_id=current_user["id"],
        title=event.title,
        start_time=event.start_time,
        end_time=event.end_time,
        status="BUSY"
    )
    events_db.append(new_event)
    return {"message": "Event created", "event": new_event}

@app.patch("/events/{event_id}/status")
def update_event_status(event_id: int, body: StatusUpdate, current_user: dict = Depends(get_current_user)):
    for e in events_db:
        if e.id == event_id and e.user_id == current_user["id"]:
            e.status = body.status
            return {"message": f"Event {event_id} updated", "event": e}
    raise HTTPException(status_code=404, detail="Event not found or not yours")

@app.get("/available-slots")
def get_available_slots(current_user: dict = Depends(get_current_user)):
    available = [e for e in events_db if e.status == "AVAILABLE" and e.user_id != current_user["id"]]
    return {"available_slots": available}

@app.get("/")
def root():
    return {"message": "SlotSwapper API running!"}
