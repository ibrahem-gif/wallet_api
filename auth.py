import logging
logger = logging.getLogger("wallet")
_metrics = {"requests_total": 0}

from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from config import SECRET_KEY, ALGORITHM
from db import database

async def get_current_user(token: str = Depends(oauth2_scheme)):
    _metrics["requests_total"] += 1
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone = payload.get("sub")
        token_ver = payload.get("ver", 0)
        if not phone:
            raise HTTPException(401, "توكن غير صالح")
        user = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": phone})
        if not user:
            raise HTTPException(401, "المستخدم غير موجود")
        # التحقق من token_version - يُبطل التوكنات القديمة
        if user["token_version"] != token_ver:
            raise HTTPException(401, "انتهت صلاحية الجلسة، يرجى تسجيل الدخول مجدداً")
        if user["is_banned"]:
            raise HTTPException(403, "الحساب محظور")
        return user
    except JWTError as e:
        logger.warning("JWT خطأ: %s", e)
        raise HTTPException(401, "توكن منتهي أو غير صالح")

async def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(403, "غير مصرح - يلزم صلاحية أدمن")
    return user

async def require_seller(user=Depends(get_current_user)):
    if not user["is_seller"] or not user["seller_approved"]:
        raise HTTPException(403, "يجب أن تكون تاجراً معتمداً")
    return user