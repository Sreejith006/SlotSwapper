from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3, jwt, bcrypt

# ----------------------#
# BASIC SETUP
# ----------------------#
app = FastAPI(title="SlotSwapper API")
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"

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
    status TEXT DEFAULT 'BUSY',
    user_id INTEGER
)''')

conn.commit()

# ----------------------#
# MODELS
# ----------------------#
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class EventCreate(BaseModel):
    title: str
    start_time: str
    end_time: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ----------------------#
# HELPER FUNCTIONS
# ----------------------#
def create_token(data: dict):
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(hours=5), **data},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ----------------------#
# AUTH ROUTES
# ----------------------#
@app.post("/signup")
def signup(user: UserCreate):
    # Hash password and convert to string
    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                       (user.name, user.email, hashed_pw))
        conn.commit()
        return {"message": "User registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    cursor.execute("SELECT * FROM users WHERE email = ?", (form_data.username,))
    user = cursor.fetchone()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    stored_hash = user[3].encode('utf-8')  # convert back to bytes
    if not bcrypt.checkpw(form_data.password.encode('utf-8'), stored_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_token({"user_id": user[0], "email": user[2]})
    return {"access_token": token, "token_type": "bearer"}

# ----------------------#
# EVENT ROUTES
# ----------------------#
@app.post("/events")
def create_event(event: EventCreate, token_data: dict = Depends(verify_token)):
    user_id = token_data["user_id"]
    cursor.execute("INSERT INTO events (title, start_time, end_time, user_id) VALUES (?, ?, ?, ?)",
                   (event.title, event.start_time, event.end_time, user_id))
    conn.commit()
    return {"message": "Event created successfully"}

@app.get("/events")
def get_events(token_data: dict = Depends(verify_token)):
    user_id = token_data["user_id"]
    cursor.execute("SELECT * FROM events WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    events = [{"id": r[0], "title": r[1], "start_time": r[2], "end_time": r[3], "status": r[4]} for r in rows]
    return {"events": events}

# ----------------------#
# ROOT ENDPOINT
# ----------------------#
@app.get("/")
def home():
    return {"message": "✅ SlotSwapper API is running successfully!"}
