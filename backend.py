from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import random
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# --- LOAD ENVIRONMENT VARIABLES ---
load_dotenv()

# --- CONFIGURATION ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") 
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# EMAIL CONFIGURATION
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "pairs.india.official@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "jhypazbfqudoznbd")

if not SUPABASE_URL or not SUPABASE_KEY or not SECRET_KEY:
    raise ValueError("Missing environment variables. Please check your .env file.")

# --- SETUP ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- IN-MEMORY OTP STORAGE ---
otp_storage = {}

# --- MODELS ---
class UserSignup(BaseModel):
    email: str
    password: str
    full_name: str
    phone: str

class UserLogin(BaseModel):
    email: str
    password: str

class OtpRequest(BaseModel):
    email: str

class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    full_name: str
    phone: str
    gender: str | None = None
    dob: str | None = None

class OrderItem(BaseModel):
    product_name: str
    quantity: int
    price: float
    image_url: str

class CreateOrderRequest(BaseModel):
    total_amount: float
    items: list[OrderItem]
    status: str = "COMPLETED"

# --- HELPER FUNCTIONS ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return email

# --- EMAIL SENDER ---
def send_email_otp(to_email, otp):
    try:
        msg = EmailMessage()
        msg.set_content(f"Hi,You requested to reset your password for Sarthi.Your OTP is: {otp}. This OTP will expire in 10 minutes. If you didn't request this, please ignore this email. Thanks,Sarthi Team")
        msg['Subject'] = 'Password Reset OTP - Sarthi'
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# --- ROUTES ---

@app.post("/signup")
def signup(user: UserSignup):
    # 1. Check if user exists
    existing = supabase.table("custom_users").select("email").eq("email", user.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email already registered")

    # 2. Hash Password
    hashed_pwd = get_password_hash(user.password)

    # 3. Store in Supabase
    user_data = {
        "email": user.email,
        "password_hash": hashed_pwd,
        "full_name": user.full_name,
        "phone": user.phone  # <--- FIXED LINE (Removed .get())
    }
    
    try:
        supabase.table("custom_users").insert(user_data).execute()
        return {"message": "User created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
def login(user: UserLogin):
    response = supabase.table("custom_users").select("*").eq("email", user.email).execute()
    if not response.data:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    db_user = response.data[0]

    if not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": db_user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/home-data")
def get_home_data(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome back, {current_user}! Here is your secure dashboard data."}

@app.get("/profile")
def get_profile(current_email: str = Depends(get_current_user)):
    response = supabase.table("custom_users").select("*").eq("email", current_email).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = response.data[0]
    phone_digits = user.get("phone", "0000")[-4:] 
    member_id_display = f"8834  {phone_digits}"
    
    return {
        "full_name": user.get("full_name", "Valued Member"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "member_id": member_id_display
    }

# --- FORGOT PASSWORD FLOW ---

@app.post("/request-otp")
def request_otp(data: OtpRequest):
    user = supabase.table("custom_users").select("email").eq("email", data.email).execute()
    if not user.data:
        raise HTTPException(status_code=404, detail="Email not registered")

    otp = str(random.randint(100000, 999999))
    otp_storage[data.email] = otp
    
    print("------------------------------------------------")
    print(f"🔐 GENERATED OTP FOR {data.email}: {otp}")
    print("------------------------------------------------")

    if "your-email" not in SMTP_EMAIL: 
        send_email_otp(data.email, otp)
    
    return {"message": "OTP sent successfully"}

@app.post("/verify-otp")
def verify_otp(data: VerifyOtpRequest):
    stored_otp = otp_storage.get(data.email)
    if stored_otp and stored_otp == data.otp:
        return {"message": "OTP Verified"}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP")

@app.post("/reset-password")
def reset_password(data: ResetPasswordRequest):
    if otp_storage.get(data.email) != data.otp:
        raise HTTPException(status_code=400, detail="Invalid Session or OTP")
    
    hashed_pwd = get_password_hash(data.new_password)

    try:
        supabase.table("custom_users").update({"password_hash": hashed_pwd}).eq("email", data.email).execute()
        del otp_storage[data.email]
        return {"message": "Password updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/profile")
def update_profile(data: UpdateProfileRequest, current_email: str = Depends(get_current_user)):
    # Prepare data to update
    update_data = {
        "full_name": data.full_name,
        "phone": data.phone,
        "gender": data.gender,
        "dob": data.dob
    }
    
    # Filter out None values just in case
    update_data = {k: v for k, v in update_data.items() if v is not None}

    try:
        # Update the user row where email matches the token's email
        supabase.table("custom_users").update(update_data).eq("email", current_email).execute()
        return {"message": "Profile updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/orders")
def create_order(order: CreateOrderRequest, current_email: str = Depends(get_current_user)):
    # 1. Prepare Order Data
    new_order = {
        "user_email": current_email,
        "total_amount": order.total_amount,
        "status": order.status,
        "order_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), # Simple string format
        "items": [item.dict() for item in order.items] # Store items as JSON
    }

    try:
        supabase.table("orders").insert(new_order).execute()
        return {"message": "Order placed successfully"}
    except Exception as e:
        print(f"Order Creation Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/orders")
def get_orders(current_email: str = Depends(get_current_user)):
    try:
        # Fetch orders for the logged-in user, sorted by newest first
        response = supabase.table("orders").select("*").eq("user_email", current_email).order("id", desc=True).execute()
        return response.data
    except Exception as e:
        print(f"Fetch Orders Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))