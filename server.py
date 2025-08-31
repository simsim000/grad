from fastapi import FastAPI, APIRouter, HTTPException, Depends, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
from enum import Enum
import base64

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key-here')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

class UserRole(str, Enum):
    STUDENT = "student"
    ALUMNI = "alumni"
    FACULTY = "faculty"
    ADMIN = "admin"

class VerificationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class PostType(str, Enum):
    QUESTION = "question"
    JOB = "job"
    INTERNSHIP = "internship"
    MENTORSHIP = "mentorship"

# User Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    role: UserRole
    college_name: str
    college_email: Optional[str] = None
    linkedin_profile: Optional[str] = None
    bio: Optional[str] = None
    graduation_year: Optional[int] = None
    course: Optional[str] = None
    skills: List[str] = []
    verification_status: VerificationStatus = VerificationStatus.PENDING
    id_card_photo: Optional[str] = None  # base64 encoded
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: UserRole
    college_name: str
    college_email: Optional[str] = None
    linkedin_profile: Optional[str] = None
    bio: Optional[str] = None
    graduation_year: Optional[int] = None
    course: Optional[str] = None
    skills: List[str] = []

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    college_name: str
    linkedin_profile: Optional[str] = None
    bio: Optional[str] = None
    graduation_year: Optional[int] = None
    course: Optional[str] = None
    skills: List[str] = []
    verification_status: VerificationStatus
    is_active: bool
    created_at: datetime

# Post Models
class Post(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    post_type: PostType
    author_id: str
    college_name: str
    tags: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

class PostCreate(BaseModel):
    title: str
    content: str
    post_type: PostType
    tags: List[str] = []

class PostResponse(BaseModel):
    id: str
    title: str
    content: str
    post_type: PostType
    author_id: str
    author_name: str
    college_name: str
    tags: List[str] = []
    created_at: datetime
    updated_at: datetime

# Mentorship Models
class MentorshipSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mentor_id: str
    title: str
    description: str
    topic: str
    scheduled_time: datetime
    duration_minutes: int = 60
    max_participants: int = 1
    college_name: str
    meet_link: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MentorshipSessionCreate(BaseModel):
    title: str
    description: str
    topic: str
    scheduled_time: datetime
    duration_minutes: int = 60
    max_participants: int = 1

class MentorshipBooking(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    student_id: str
    booked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "confirmed"

# Authentication helpers
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = await db.users.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

# Routes
@api_router.get("/")
async def root():
    return {"message": "GradLink API - Connecting Students and Alumni"}

@api_router.post("/register", response_model=dict)
async def register_user(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash password
    hashed_password = hash_password(user_data.password)
    
    # Create user object
    user_dict = user_data.dict()
    user_dict.pop('password')
    user_obj = User(**user_dict)
    
    # Store user with hashed password
    user_doc = user_obj.dict()
    user_doc['password_hash'] = hashed_password
    
    await db.users.insert_one(user_doc)
    
    # Create access token
    access_token = create_access_token(data={"sub": user_obj.email})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse(**user_obj.dict())
    }

@api_router.post("/login", response_model=dict)
async def login_user(user_credentials: UserLogin):
    user = await db.users.find_one({"email": user_credentials.email})
    if not user or not verify_password(user_credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user['email']})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse(**user)
    }

@api_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.dict())

@api_router.get("/colleges", response_model=List[str])
async def get_colleges():
    colleges = await db.users.distinct("college_name")
    return colleges

@api_router.get("/posts", response_model=List[PostResponse])
async def get_posts(
    college_name: Optional[str] = None,
    post_type: Optional[PostType] = None,
    current_user: User = Depends(get_current_user)
):
    query = {"is_active": True}
    
    # Users can only see posts from their college
    if current_user.role != UserRole.ADMIN:
        query["college_name"] = current_user.college_name
    elif college_name:
        query["college_name"] = college_name
    
    if post_type:
        query["post_type"] = post_type
    
    posts = await db.posts.find(query).sort("created_at", -1).to_list(100)
    
    # Get author names
    result = []
    for post in posts:
        author = await db.users.find_one({"id": post["author_id"]})
        post_response = PostResponse(
            **post,
            author_name=author["full_name"] if author else "Unknown"
        )
        result.append(post_response)
    
    return result

@api_router.post("/posts", response_model=PostResponse)
async def create_post(
    post_data: PostCreate,
    current_user: User = Depends(get_current_user)
):
    post_dict = post_data.dict()
    post_dict["author_id"] = current_user.id
    post_dict["college_name"] = current_user.college_name
    
    post_obj = Post(**post_dict)
    await db.posts.insert_one(post_obj.dict())
    
    return PostResponse(
        **post_obj.dict(),
        author_name=current_user.full_name
    )

@api_router.get("/mentorship-sessions", response_model=List[dict])
async def get_mentorship_sessions(current_user: User = Depends(get_current_user)):
    query = {
        "is_active": True,
        "college_name": current_user.college_name,
        "scheduled_time": {"$gte": datetime.now(timezone.utc)}
    }
    
    sessions = await db.mentorship_sessions.find(query).sort("scheduled_time", 1).to_list(50)
    
    # Get mentor names and booking counts
    result = []
    for session in sessions:
        mentor = await db.users.find_one({"id": session["mentor_id"]})
        bookings_count = await db.mentorship_bookings.count_documents({"session_id": session["id"]})
        
        session_data = session.copy()
        session_data["mentor_name"] = mentor["full_name"] if mentor else "Unknown"
        session_data["available_spots"] = session["max_participants"] - bookings_count
        result.append(session_data)
    
    return result

@api_router.post("/mentorship-sessions", response_model=dict)
async def create_mentorship_session(
    session_data: MentorshipSessionCreate,
    current_user: User = Depends(get_current_user)
):
    if current_user.role not in [UserRole.ALUMNI, UserRole.FACULTY]:
        raise HTTPException(status_code=403, detail="Only alumni and faculty can create mentorship sessions")
    
    session_dict = session_data.dict()
    session_dict["mentor_id"] = current_user.id
    session_dict["college_name"] = current_user.college_name
    
    # Generate Google Meet link (simplified - in production, integrate with Google Meet API)
    meet_id = str(uuid.uuid4())[:10]
    session_dict["meet_link"] = f"https://meet.google.com/{meet_id}"
    
    session_obj = MentorshipSession(**session_dict)
    await db.mentorship_sessions.insert_one(session_obj.dict())
    
    return {"message": "Mentorship session created successfully", "session": session_obj.dict()}

@api_router.post("/mentorship-sessions/{session_id}/book", response_model=dict)
async def book_mentorship_session(
    session_id: str,
    current_user: User = Depends(get_current_user)
):
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(status_code=403, detail="Only students can book mentorship sessions")
    
    # Check if session exists and is available
    session = await db.mentorship_sessions.find_one({"id": session_id, "is_active": True})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Check if student is from same college
    if session["college_name"] != current_user.college_name:
        raise HTTPException(status_code=403, detail="You can only book sessions from your college")
    
    # Check availability
    bookings_count = await db.mentorship_bookings.count_documents({"session_id": session_id})
    if bookings_count >= session["max_participants"]:
        raise HTTPException(status_code=400, detail="Session is fully booked")
    
    # Check if already booked
    existing_booking = await db.mentorship_bookings.find_one({
        "session_id": session_id,
        "student_id": current_user.id
    })
    if existing_booking:
        raise HTTPException(status_code=400, detail="You have already booked this session")
    
    # Create booking
    booking = MentorshipBooking(session_id=session_id, student_id=current_user.id)
    await db.mentorship_bookings.insert_one(booking.dict())
    
    return {
        "message": "Session booked successfully",
        "meet_link": session["meet_link"],
        "scheduled_time": session["scheduled_time"]
    }

@api_router.post("/upload-id-card")
async def upload_id_card(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if file.content_type not in ["image/jpeg", "image/png", "image/jpg"]:
        raise HTTPException(status_code=400, detail="Only JPEG and PNG files are allowed")
    
    # Read file and encode to base64
    file_content = await file.read()
    encoded_image = base64.b64encode(file_content).decode('utf-8')
    
    # Update user with ID card photo
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"id_card_photo": encoded_image, "verification_status": "pending"}}
    )
    
    return {"message": "ID card uploaded successfully. Awaiting admin verification."}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()