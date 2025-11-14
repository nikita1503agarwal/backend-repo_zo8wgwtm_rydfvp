import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents

app = FastAPI(title="Madrasah API", description="Backend for a modern madrasah website with admin login and dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    token: str
    name: str
    role: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_default_admin():
    """Ensure there's at least one admin user."""
    from bson import ObjectId  # type: ignore
    try:
        existing = db["adminuser"].find_one({"username": "admin"}) if db else None
        if not existing and db:
            db["adminuser"].insert_one({
                "name": "Administrator",
                "email": "admin@example.com",
                "username": "admin",
                "password_hash": hash_password("admin123"),
                "role": "admin",
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            })
    except Exception:
        # if db isn't configured, ignore
        pass


@app.on_event("startup")
async def startup_event():
    create_default_admin()


@app.get("/")
def read_root():
    return {"message": "Madrasah Backend Running"}


@app.post("/api/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    if db is None:
        # For environments without DB configured, allow demo login
        if payload.username == "admin" and payload.password == "admin123":
            return {"token": "demo-token", "name": "Administrator", "role": "admin"}
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["adminuser"].find_one({"username": payload.username, "is_active": True})
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    if user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_hex(24)
    expires = datetime.now(timezone.utc) + timedelta(hours=8)
    db["session"].insert_one({
        "user_id": str(user.get("_id")),
        "token": token,
        "role": user.get("role", "admin"),
        "expires_at": expires,
        "revoked": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    })
    return {"token": token, "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


def require_auth(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = authorization.replace("Bearer ", "")
    if db is None:
        if token == "demo-token":
            return {"role": "admin", "name": "Administrator"}
        raise HTTPException(status_code=401, detail="Invalid token")

    session = db["session"].find_one({"token": token, "revoked": False})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid token")
    if session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Token expired")
    return session


@app.get("/api/dashboard")
def dashboard(auth = Depends(require_auth)):
    # Example dashboard data
    stats = {
        "students": 1240,
        "teachers": 68,
        "classes": 32,
        "alumni": 5400,
    }
    announcements = [
        {"title": "Penerimaan Santri Baru", "date": "2025-06-01"},
        {"title": "Ujian Akhir Semester", "date": "2025-12-15"},
    ]
    return {"user": {"name": auth.get("name", "Administrator")}, "stats": stats, "announcements": announcements}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    # Check environment variables
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
