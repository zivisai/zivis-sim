# auth.py
# VULNERABILITY: Authentication and Session Vulnerabilities
# This module implements intentionally flawed authentication
# Attack vectors: Session hijacking, IDOR, broken authentication

import os
import uuid
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException, Cookie, Response, Header
from pydantic import BaseModel

router = APIRouter(prefix="/api/auth", tags=["Authentication Vulnerabilities"])

# ============================================================================
# INSECURE DATA STORES
# ============================================================================

# VULNERABILITY: In-memory storage, no encryption
users_db: Dict[str, dict] = {
    "admin": {
        "password": "admin123",  # VULNERABILITY: Weak password
        "role": "admin",
        "api_key": "sk-admin-secret-key-12345",  # VULNERABILITY: Predictable API key
        "email": "admin@zivis-sim.local"
    },
    "user1": {
        "password": "password",  # VULNERABILITY: Common password
        "role": "user",
        "api_key": "sk-user1-key-67890",
        "email": "user1@zivis-sim.local"
    },
    "guest": {
        "password": "guest",
        "role": "guest",
        "api_key": "sk-guest-key-11111",
        "email": "guest@zivis-sim.local"
    }
}

# VULNERABILITY: Sessions stored insecurely with predictable IDs
sessions_db: Dict[str, dict] = {}

# VULNERABILITY: Sequential user IDs
next_user_id = 1000


# ============================================================================
# REQUEST MODELS
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str

class PasswordResetRequest(BaseModel):
    email: str

class UpdateProfileRequest(BaseModel):
    user_id: int
    email: Optional[str] = None
    role: Optional[str] = None


# ============================================================================
# VULNERABLE ENDPOINTS
# ============================================================================

@router.post("/login")
async def login(request: LoginRequest, response: Response):
    """
    Login with username and password.

    VULNERABILITIES:
    - No rate limiting (brute force possible)
    - Timing attack possible (different response times)
    - Verbose error messages
    - Predictable session tokens

    ATTACK EXAMPLES:
    - Brute force common passwords
    - Enumerate valid usernames via error messages
    - Timing attack to determine valid usernames
    """
    # VULNERABILITY: Different error messages reveal valid usernames
    if request.username not in users_db:
        raise HTTPException(status_code=401, detail=f"User '{request.username}' not found")

    user = users_db[request.username]

    # VULNERABILITY: Plain text password comparison
    if user["password"] != request.password:
        raise HTTPException(status_code=401, detail="Invalid password")

    # VULNERABILITY: Predictable session token (timestamp + username hash)
    timestamp = int(datetime.now().timestamp())
    session_token = f"{timestamp}-{hashlib.md5(request.username.encode()).hexdigest()[:8]}"

    sessions_db[session_token] = {
        "username": request.username,
        "role": user["role"],
        "created_at": datetime.now().isoformat(),
        "api_key": user["api_key"]  # VULNERABILITY: API key in session
    }

    # VULNERABILITY: Session token in cookie without security flags
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=False,  # VULNERABILITY: Accessible via JavaScript (XSS)
        secure=False,    # VULNERABILITY: Sent over HTTP
        samesite="none"  # VULNERABILITY: No CSRF protection
    )

    return {
        "message": "Login successful",
        "session_token": session_token,  # VULNERABILITY: Token in response body
        "user": {
            "username": request.username,
            "role": user["role"],
            "api_key": user["api_key"]  # VULNERABILITY: API key exposed
        }
    }


@router.post("/register")
async def register(request: RegisterRequest):
    """
    Register a new user.

    VULNERABILITIES:
    - No password requirements
    - No email verification
    - Sequential user IDs (enumerable)
    - Role can be manipulated

    ATTACK: Register with role=admin in request body
    """
    global next_user_id

    if request.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    # VULNERABILITY: No password strength requirements
    # VULNERABILITY: Sequential predictable user ID
    user_id = next_user_id
    next_user_id += 1

    # VULNERABILITY: Predictable API key generation
    api_key = f"sk-{request.username}-{user_id}"

    users_db[request.username] = {
        "user_id": user_id,
        "password": request.password,  # VULNERABILITY: Stored in plain text
        "role": "user",  # Default role, but see /register/admin below
        "api_key": api_key,
        "email": request.email
    }

    return {
        "message": "User registered",
        "user_id": user_id,
        "api_key": api_key  # VULNERABILITY: API key immediately exposed
    }


@router.post("/register/admin")
async def register_admin(request: RegisterRequest, admin_code: Optional[str] = None):
    """
    Register as admin.

    VULNERABILITY: Weak admin code protection
    The admin code is hardcoded and easily guessable
    """
    # VULNERABILITY: Hardcoded, weak admin registration code
    if admin_code != "zivis-admin-2024":
        raise HTTPException(status_code=403, detail="Invalid admin code")

    global next_user_id
    user_id = next_user_id
    next_user_id += 1

    users_db[request.username] = {
        "user_id": user_id,
        "password": request.password,
        "role": "admin",  # VULNERABILITY: Anyone with code becomes admin
        "api_key": f"sk-admin-{request.username}-{user_id}",
        "email": request.email
    }

    return {"message": "Admin user registered", "user_id": user_id}


@router.get("/session/{session_token}")
async def get_session(session_token: str):
    """
    Get session information.

    VULNERABILITY: IDOR - can view any session
    No validation that requester owns the session
    """
    if session_token not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")

    # VULNERABILITY: Full session data exposed including API key
    return sessions_db[session_token]


@router.get("/sessions")
async def list_all_sessions():
    """
    List all active sessions.

    VULNERABILITY: Information disclosure
    Reveals all active sessions and their tokens
    """
    return {
        "sessions": [
            {
                "token": token,
                "username": data["username"],
                "role": data["role"],
                "created_at": data["created_at"]
            }
            for token, data in sessions_db.items()
        ]
    }


@router.get("/user/{user_id}")
async def get_user_by_id(user_id: int):
    """
    Get user information by ID.

    VULNERABILITY: IDOR - can view any user
    No authorization check
    """
    for username, user_data in users_db.items():
        if user_data.get("user_id") == user_id:
            # VULNERABILITY: Returns sensitive data including password hash
            return {
                "username": username,
                **user_data
            }

    raise HTTPException(status_code=404, detail="User not found")


@router.put("/user/{user_id}")
async def update_user(user_id: int, request: UpdateProfileRequest):
    """
    Update user profile.

    VULNERABILITIES:
    - IDOR: Can update any user's profile
    - Mass assignment: Can change role to admin
    - No current password verification
    """
    for username, user_data in users_db.items():
        if user_data.get("user_id") == user_id:
            if request.email:
                user_data["email"] = request.email
            if request.role:
                # VULNERABILITY: Can elevate to admin!
                user_data["role"] = request.role

            return {"message": "User updated", "user": user_data}

    raise HTTPException(status_code=404, detail="User not found")


@router.post("/password-reset")
async def password_reset(request: PasswordResetRequest):
    """
    Request password reset.

    VULNERABILITIES:
    - Predictable reset tokens
    - Token exposed in response
    - No expiration
    """
    # Find user by email
    for username, user_data in users_db.items():
        if user_data.get("email") == request.email:
            # VULNERABILITY: Predictable reset token
            reset_token = hashlib.md5(f"{request.email}-reset".encode()).hexdigest()

            return {
                "message": "Password reset initiated",
                # VULNERABILITY: Token directly in response
                "reset_token": reset_token,
                "reset_url": f"/api/auth/reset/{reset_token}"
            }

    # VULNERABILITY: Reveals email existence
    raise HTTPException(status_code=404, detail=f"No user with email {request.email}")


@router.post("/reset/{reset_token}")
async def reset_password(reset_token: str, new_password: str):
    """
    Reset password with token.

    VULNERABILITY: Token not validated properly
    Any valid-looking token might work
    """
    # VULNERABILITY: Weak token validation
    if len(reset_token) == 32:  # Just checks length!
        return {
            "message": "Password reset successful",
            "note": "In real implementation, this would change the password"
        }

    raise HTTPException(status_code=400, detail="Invalid reset token")


@router.get("/api-key")
async def get_api_key(session_token: str = Cookie(default=None)):
    """
    Get API key for authenticated user.

    VULNERABILITY: Session token from cookie without validation
    """
    if not session_token:
        raise HTTPException(status_code=401, detail="No session token")

    if session_token not in sessions_db:
        raise HTTPException(status_code=401, detail="Invalid session")

    session = sessions_db[session_token]

    return {
        "api_key": session["api_key"],
        "username": session["username"]
    }


@router.get("/users")
async def list_users(x_admin_key: Optional[str] = Header(default=None)):
    """
    List all users (admin only).

    VULNERABILITY: Weak admin check
    The admin key is hardcoded and easily guessable
    """
    # VULNERABILITY: Hardcoded admin key
    if x_admin_key != "super-secret-admin-key":
        raise HTTPException(status_code=403, detail="Admin access required")

    # VULNERABILITY: Returns all user data including passwords
    return {"users": users_db}


@router.post("/impersonate/{username}")
async def impersonate_user(username: str, response: Response):
    """
    Impersonate another user (for testing).

    VULNERABILITY: No proper authorization
    Should require admin but doesn't verify properly
    """
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    # VULNERABILITY: Creates valid session for any user without authentication
    session_token = f"impersonated-{uuid.uuid4()}"
    user = users_db[username]

    sessions_db[session_token] = {
        "username": username,
        "role": user["role"],
        "created_at": datetime.now().isoformat(),
        "api_key": user["api_key"],
        "impersonated": True
    }

    response.set_cookie(key="session_token", value=session_token)

    return {
        "message": f"Now impersonating {username}",
        "session_token": session_token
    }


@router.delete("/session/{session_token}")
async def logout(session_token: str):
    """
    Logout / invalidate session.

    VULNERABILITY: Can logout any user by knowing their session token
    """
    if session_token in sessions_db:
        del sessions_db[session_token]
        return {"message": "Session invalidated"}

    raise HTTPException(status_code=404, detail="Session not found")
