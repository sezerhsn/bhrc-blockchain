# ──────────────────────────────────────────────

# 🔒 This file is part of the BHRC Blockchain Project

# 📛 Author: Sezer H.

# 📨 Contact: sezerhsn@gmail.com

# 🔗 GitHub: https://github.com/sezerhsn/bhrc-blockchain

# 📜 License: MIT License (see LICENSE file for details)

# ──────────────────────────────────────────────

from fastapi import APIRouter, Depends, Form, HTTPException, Response, Request
from fastapi.responses import JSONResponse
from typing import Dict
from pydantic import BaseModel
from bhrc_blockchain.api.auth import create_access_token, get_current_user, get_current_admin, admin_required
from bhrc_blockchain.core.logger.logging_utils import setup_logger
from bhrc_blockchain.database.database import SessionLocal
from bhrc_blockchain.database.models import SessionLog, User

router = APIRouter()
logger = setup_logger("AuthRoutes")

fake_users = {
    "admin": "admin123",
    "demo": "demo123"
}

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    message: str

@router.post("/token", response_model=TokenResponse)
def login(response: Response, username: str = Form(...), password: str = Form(...), request: Request = None):
    """
    Kullanıcı girişi ve JWT token üretimi (Set-Cookie ile)
    """
    if username in fake_users and fake_users[username] == password:
        access_token = create_access_token(data={"sub": username})

        session = SessionLocal()
        session_log = SessionLog(
            user_id=0,
            username=username,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None
        )
        session.add(session_log)
        session.commit()

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="Lax",
            secure=True
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "message": f"Giriş başarılı: {username}"
        }

    raise HTTPException(status_code=401, detail="Giriş reddedildi")

@router.get("/me", response_model=Dict[str, str])
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "message": "Kullanıcı token ile doğrulandı",
        "username": current_user.get("sub", "bilinmiyor")
    }

@router.post("/refresh", response_model=Dict[str, str])
def refresh_token(current_user: dict = Depends(get_current_user)):
    sub = current_user.get("sub", "anon")
    new_token = create_access_token(data={"sub": sub})
    return {"access_token": new_token, "token_type": "bearer"}

@router.post("/logout")
def logout(current_user: dict = Depends(get_current_admin)):
    session = SessionLocal()

    log = session.query(SessionLog).filter_by(username=current_user["sub"], active=True).order_by(SessionLog.login_time.desc()).first()
    if log:
        log.active = False
        session.commit()

    response = JSONResponse(content={"message": "Çıkış yapıldı"})
    response.delete_cookie("access_token")
    return response

@router.get("/status")
def auth_status():
    return {"status": "Auth sistemi aktif", "login_required": True}

@router.get("/admin-action")
def protected_admin_action(current_user: dict = Depends(admin_required("admin"))):
    return {
        "message": "Admin işlemi başarıyla çalıştı.",
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }

@router.get("/super-admin-action")
def protected_super_admin_action(current_user: dict = Depends(admin_required("super_admin"))):
    return {
        "message": "Super admin işlemi başarıyla çalıştı.",
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }

@router.get("/log-access")
def view_logs_permission_check(current_user: dict = Depends(admin_required("admin", required_permission="view_logs"))):
    return {
        "message": "Log erişimine izin verildi",
        "user": current_user.get("sub")
    }

