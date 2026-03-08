import json
import base64
import io
import pyotp
import qrcode
import uvicorn
from typing import Optional
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

# WebAuthn Helpers
from webauthn import (
    generate_registration_options, 
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

# Database Imports
from app.models import SessionLocal, UserCredential, User

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

# In-memory store for challenges (Use Redis for production)
challenge_store = {}

# Configuration
RP_ID = "localhost"
RP_NAME = "Enterprise MFA System"
ORIGIN = "http://localhost:8000"

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Schemas ---
class RegVerificationRequest(BaseModel):
    username: str
    attestation: dict

class AuthVerificationRequest(BaseModel):
    username: str
    authentication: dict

class TOTPVerifyRequest(BaseModel):
    username: str
    code: str

# --- ROUTES ---

@app.get("/")
async def serve_home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# --- REGISTRATION & TOTP SETUP ---

@app.get("/generate-registration-options")
async def get_reg_options(username: str, db: Session = Depends(get_db)):
    # Ensure user exists in the DB first
    user = db.query(User).filter_by(username=username).first()
    if not user:
        user = User(username=username)
        db.add(user)
        db.commit()

    options = generate_registration_options(
        rp_name=RP_NAME, 
        rp_id=RP_ID, 
        user_id=username.encode(), 
        user_name=username
    )
    challenge_store[username] = options.challenge
    return JSONResponse(content=json.loads(options_to_json(options)))

@app.post("/verify-registration")
async def verify_reg(data: RegVerificationRequest, db: Session = Depends(get_db)):
    challenge = challenge_store.get(data.username)
    if not challenge:
        return JSONResponse(status_code=400, content={"error": "Challenge expired"})

    try:
        verification = verify_registration_response(
            credential=data.attestation,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True
        )
        
        new_cred = UserCredential(
            id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            username=data.username
        )
        db.add(new_cred)
        db.commit()
        
        # Generate TOTP Secret for the user during registration
        user = db.query(User).filter_by(username=data.username).first()
        user.totp_secret = pyotp.random_base32()
        db.commit()

        # Generate QR Code for Frontend
        totp = pyotp.totp.TOTP(user.totp_secret)
        uri = totp.provisioning_uri(name=data.username, issuer_name=RP_NAME)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf)
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return {
            "verified": True, 
            "totp_qr": qr_b64, 
            "totp_secret": user.totp_secret
        }
        
    except Exception as e:
        return JSONResponse(status_code=400, content={"verified": False, "error": str(e)})

# --- AUTHENTICATION (LOGIN) FLOW ---

@app.get("/generate-authentication-options")
async def get_auth_options(username: str, db: Session = Depends(get_db)):
    user_creds = db.query(UserCredential).filter_by(username=username).all()
    if not user_creds:
        return JSONResponse(status_code=404, content={"error": "User not registered"})

    allow_credentials = [PublicKeyCredentialDescriptor(id=cred.id) for cred in user_creds]
    options = generate_authentication_options(rp_id=RP_ID, allow_credentials=allow_credentials)
    challenge_store[username] = options.challenge
    
    return JSONResponse(content=json.loads(options_to_json(options)))

@app.post("/verify-authentication")
async def verify_auth(data: AuthVerificationRequest, db: Session = Depends(get_db)):
    try:
        challenge = challenge_store.get(data.username)
        cred_id_str = data.authentication.get('id')
        
        # Decode Base64URL string to bytes
        padding = '=' * (4 - len(cred_id_str) % 4)
        cred_id_bytes = base64.urlsafe_b64decode(cred_id_str + padding)
        
        db_cred = db.query(UserCredential).filter_by(id=cred_id_bytes).first()
        user = db.query(User).filter_by(username=data.username).first()

        if not challenge or not db_cred:
            return JSONResponse(status_code=400, content={"verified": False, "error": "Invalid session"})

        verification = verify_authentication_response(
            credential=data.authentication,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=db_cred.public_key,
            credential_current_sign_count=db_cred.sign_count,
            require_user_verification=True
        )
        
        db_cred.sign_count = verification.new_sign_count
        db.commit()
        
        # Check if 2FA (TOTP) is needed
        if user and user.totp_secret:
            return {"verified": True, "requires_totp": True}

        return {"verified": True, "requires_totp": False}

    except Exception as e:
        return JSONResponse(status_code=400, content={"verified": False, "error": str(e)})

@app.post("/verify-totp")
async def verify_totp(data: TOTPVerifyRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=data.username).first()
    if not user or not user.totp_secret:
        return JSONResponse(status_code=400, content={"error": "MFA not configured"})

    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(data.code):
        # Final Step: Issue session cookie
        response.set_cookie(key="session_user", value=data.username, httponly=True, samesite="strict")
        return {"success": True}
    
    return JSONResponse(status_code=400, content={"success": False, "error": "Invalid Code"})

@app.get("/dashboard")
async def serve_dashboard(request: Request):
    username = request.cookies.get("session_user")
    if not username:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return templates.TemplateResponse("dashboard.html", {"request": request, "username": username})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)