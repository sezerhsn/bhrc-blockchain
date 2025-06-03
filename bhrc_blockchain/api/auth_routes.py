from fastapi import APIRouter, Depends, Form, HTTPException, Response
from fastapi.responses import JSONResponse
from typing import Dict
from pydantic import BaseModel
from bhrc_blockchain.api.auth import create_access_token, get_current_user
from bhrc_blockchain.core.logger.logging_utils import setup_logger

router = APIRouter()
logger = setup_logger("AuthRoutes")

# 🚨 Geçici kullanıcılar (test amaçlı)
fake_users = {
    "admin": "admin123",
    "demo": "demo123"
}

# 🎫 Token yanıt modeli
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    message: str

# 🔐 Giriş işlemi (cookie tabanlı)
@router.post("/token", response_model=TokenResponse)
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    """
    Kullanıcı girişi ve JWT token üretimi (Set-Cookie ile)
    """
    if username in fake_users and fake_users[username] == password:
        access_token = create_access_token(data={"sub": username})

        # 🍪 JWT token'ı cookie olarak ayarla
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="Lax",
            secure=False  # HTTPS kullanıyorsan True yapabilirsin
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "message": f"Giriş başarılı: {username}"
        }

    raise HTTPException(status_code=401, detail="Giriş reddedildi")


# 🙋‍♂️ Kullanıcı bilgisi döndür (JWT içinden)
@router.get("/me", response_model=Dict[str, str])
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "message": "Kullanıcı token ile doğrulandı",
        "username": current_user.get("sub", "bilinmiyor")
    }

# 🔄 Token yenileme
@router.post("/refresh", response_model=Dict[str, str])
def refresh_token(current_user: dict = Depends(get_current_user)):
    new_token = create_access_token(data={"sub": current_user["sub"]})
    return {"access_token": new_token, "token_type": "bearer"}

# 🚪 Çıkış işlemi (cookie silinir)
@router.post("/logout", status_code=204)
def logout(response: Response, current_user: dict = Depends(get_current_user)):
    response.delete_cookie("access_token")
    logger.info(f"Kullanıcı çıkış yaptı: {current_user['sub']}")
    return

# ✅ Servis durumu kontrolü
@router.get("/status")
def auth_status():
    return {"status": "Auth sistemi aktif", "login_required": True}

