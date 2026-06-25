from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, Form, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, field_validator
from typing import Optional, List
import databases
import sqlalchemy
import bcrypt
import os
import hashlib
import hmac
import logging
import time
import uuid
import aiofiles
import asyncio
import re
from decimal import Decimal, ROUND_DOWN, InvalidOperation
from pathlib import Path
from starlette.middleware.base import BaseHTTPMiddleware
from tronpy import Tron
from tronpy.keys import PrivateKey
from tronpy.providers import HTTPProvider
from cryptography.fernet import Fernet
from jose import JWTError, jwt
from datetime import datetime, timedelta
import httpx
import random
import string
from config import *
from chat_direct import router as chat_router, create_tables
from auth import get_current_user
from db import database


# ====== Logging ======

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("wallet")

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY يجب أن يكون 32 حرف على الأقل")
if not ENCRYPT_KEY:
    raise RuntimeError("ENCRYPT_KEY غير مضبوط")

fernet = Fernet(ENCRYPT_KEY.encode())
client = Tron(HTTPProvider(api_key=TRON_API_KEY))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
limiter = Limiter(key_func=get_remote_address)

Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(f"{UPLOAD_DIR}/products").mkdir(parents=True, exist_ok=True)
Path(f"{UPLOAD_DIR}/avatars").mkdir(parents=True, exist_ok=True)

# ====== Security Headers Middleware ======
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

# ====== Request ID Middleware ======
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start_time = time.monotonic()
        response = await call_next(request)
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "method=%s path=%s status=%s duration_ms=%s",
            request.method, request.url.path, response.status_code, duration_ms,
            extra={"request_id": request_id}
        )
        return response
app = FastAPI(
    title="USDT Pro",
    docs_url=None,
    redoc_url=None
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    allow_credentials=True,
)
app.mount("/uploads/avatars", StaticFiles(directory=f"{UPLOAD_DIR}/avatars"), name="avatars")

# ====== قاعدة البيانات ======
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table("users", metadata,
    sqlalchemy.Column("phone", sqlalchemy.String(20), primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(100)),
    sqlalchemy.Column("email", sqlalchemy.String(200)),
    sqlalchemy.Column("password", sqlalchemy.String(200)),
    sqlalchemy.Column("balance", sqlalchemy.Numeric(precision=18, scale=6), default=0),
    sqlalchemy.Column("is_admin", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("is_banned", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("is_seller", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("seller_approved", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("shop_name", sqlalchemy.String(200), nullable=True),
    sqlalchemy.Column("shop_description", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("avatar_url", sqlalchemy.String(500), nullable=True),
    sqlalchemy.Column("telegram_chat_id", sqlalchemy.String(50), nullable=True),
    sqlalchemy.Column("referral_code", sqlalchemy.String(20), nullable=True),
    sqlalchemy.Column("referred_by", sqlalchemy.String(20), nullable=True),
    sqlalchemy.Column("token_version", sqlalchemy.Integer, default=0),   # لإبطال جميع التوكنات
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

wallet_addresses = sqlalchemy.Table("wallet_addresses", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("user_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone", ondelete="CASCADE")),
    sqlalchemy.Column("network", sqlalchemy.String(20)),
    sqlalchemy.Column("address", sqlalchemy.String(100)),
    sqlalchemy.Column("private_key_enc", sqlalchemy.Text),
)

transactions = sqlalchemy.Table("transactions", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("user_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("type", sqlalchemy.String(50)),          # deposit / withdraw / transfer_sent / transfer_received / product_purchase / product_sale / admin_adjust / sweep
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("fee", sqlalchemy.Numeric(precision=18, scale=6), default=0),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="completed"),  # pending / processing / completed / failed
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, default=datetime.utcnow),
    sqlalchemy.Column("related_phone", sqlalchemy.String(20), nullable=True),
    sqlalchemy.Column("description", sqlalchemy.String(500), nullable=True),
    sqlalchemy.Column("tx_hash", sqlalchemy.String(100), unique=True, nullable=True),
    sqlalchemy.Column("network", sqlalchemy.String(20), nullable=True),
    sqlalchemy.Column("ref_id", sqlalchemy.String(100), nullable=True),   # معرف مرجعي داخلي
)

# ====== Ledger - دفتر الحركات المالية ======
ledger = sqlalchemy.Table("ledger", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("user_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("entry_type", sqlalchemy.String(20)),     # debit / credit
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("balance_before", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("balance_after", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("source_type", sqlalchemy.String(50)),    # deposit / withdraw / transfer / purchase / sale / admin_adjust
    sqlalchemy.Column("source_id", sqlalchemy.String(100), nullable=True),  # transaction id أو order id
    sqlalchemy.Column("description", sqlalchemy.String(500)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

processed_deposits = sqlalchemy.Table("processed_deposits", metadata,
    sqlalchemy.Column("tx_hash", sqlalchemy.String(100), primary_key=True),
    sqlalchemy.Column("user_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("confirmations", sqlalchemy.Integer),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="pending"),  # pending / confirmed / failed
    sqlalchemy.Column("network", sqlalchemy.String(20), default="TRC20"),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, default=datetime.utcnow),
)

products = sqlalchemy.Table("products", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("name", sqlalchemy.String(200)),
    sqlalchemy.Column("description", sqlalchemy.Text),
    sqlalchemy.Column("price", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("seller_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("category", sqlalchemy.String(100), nullable=True),
    sqlalchemy.Column("product_type", sqlalchemy.String(20), default="digital"),
    sqlalchemy.Column("thumbnail_url", sqlalchemy.String(500), nullable=True),
    sqlalchemy.Column("is_active", sqlalchemy.SmallInteger, default=1),
    sqlalchemy.Column("total_sales", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("rating_avg", sqlalchemy.Numeric(precision=3, scale=1), default=0),
    sqlalchemy.Column("rating_count", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

product_files = sqlalchemy.Table("product_files", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("product_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("products.id", ondelete="CASCADE")),
    sqlalchemy.Column("file_url", sqlalchemy.String(500)),
    sqlalchemy.Column("file_name", sqlalchemy.String(300)),
    sqlalchemy.Column("file_type", sqlalchemy.String(20)),
    sqlalchemy.Column("file_size", sqlalchemy.BigInteger),
    sqlalchemy.Column("is_preview", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

orders = sqlalchemy.Table("orders", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("buyer_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("seller_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("product_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("products.id")),
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("platform_fee", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("seller_amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="completed"),
    sqlalchemy.Column("download_token", sqlalchemy.String(64), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

withdrawals = sqlalchemy.Table("withdrawals", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("user_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("to_address", sqlalchemy.String(100)),
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("fee", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("net_amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("network", sqlalchemy.String(20), default="TRC20"),
    sqlalchemy.Column("tx_hash", sqlalchemy.String(100), nullable=True),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="pending"),   # pending / processing / completed / failed
    sqlalchemy.Column("otp_verified_at", sqlalchemy.DateTime, nullable=True),
    sqlalchemy.Column("completed_at", sqlalchemy.DateTime, nullable=True),
    sqlalchemy.Column("failed_reason", sqlalchemy.String(500), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

reviews = sqlalchemy.Table("reviews", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("order_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("orders.id")),
    sqlalchemy.Column("product_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("products.id")),
    sqlalchemy.Column("buyer_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("rating", sqlalchemy.SmallInteger),
    sqlalchemy.Column("comment", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

platform_account = sqlalchemy.Table("platform_account", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("type", sqlalchemy.String(50)),
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("description", sqlalchemy.String(500)),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime, default=datetime.utcnow),
)

otp_table = sqlalchemy.Table("otp_codes", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("phone", sqlalchemy.String(20)),
    sqlalchemy.Column("code_hash", sqlalchemy.String(200)),    # مُخزن كـ hash وليس plain text
    sqlalchemy.Column("purpose", sqlalchemy.String(50)),
    sqlalchemy.Column("used", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("attempts", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("expires_at", sqlalchemy.DateTime),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

daily_withdrawals = sqlalchemy.Table("daily_withdrawals", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("amount", sqlalchemy.Numeric(precision=18, scale=6)),
    sqlalchemy.Column("date", sqlalchemy.String(10)),
)

refresh_tokens = sqlalchemy.Table("refresh_tokens", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone", ondelete="CASCADE")),
    sqlalchemy.Column("token_hash", sqlalchemy.String(200), unique=True),   # مُخزن كـ hash
    sqlalchemy.Column("expires_at", sqlalchemy.DateTime),
    sqlalchemy.Column("is_revoked", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("ip_address", sqlalchemy.String(50), nullable=True),
    sqlalchemy.Column("user_agent", sqlalchemy.String(500), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

audit_logs = sqlalchemy.Table("audit_logs", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("admin_phone", sqlalchemy.String(20)),
    sqlalchemy.Column("action", sqlalchemy.String(100)),
    sqlalchemy.Column("target_phone", sqlalchemy.String(20), nullable=True),
    sqlalchemy.Column("target_id", sqlalchemy.String(100), nullable=True),
    sqlalchemy.Column("details", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("ip_address", sqlalchemy.String(50), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

chat_messages = sqlalchemy.Table("chat_messages", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("sender_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("receiver_phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("message", sqlalchemy.Text),
    sqlalchemy.Column("message_type", sqlalchemy.String(20), default="text"),
    sqlalchemy.Column("is_read", sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
)

seller_requests = sqlalchemy.Table("seller_requests", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("phone", sqlalchemy.String(20), sqlalchemy.ForeignKey("users.phone")),
    sqlalchemy.Column("shop_name", sqlalchemy.String(200)),
    sqlalchemy.Column("shop_description", sqlalchemy.Text),
    sqlalchemy.Column("product_types", sqlalchemy.String(500)),
    sqlalchemy.Column("is_digital", sqlalchemy.SmallInteger, default=1),
    sqlalchemy.Column("extra_info", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("status", sqlalchemy.String(20), default="pending"),
    sqlalchemy.Column("admin_note", sqlalchemy.Text, nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=datetime.utcnow),
    sqlalchemy.Column("reviewed_at", sqlalchemy.DateTime, nullable=True),
)

# ====== Indexes ======
sqlalchemy.Index("idx_users_referral_code", users.c.referral_code)
sqlalchemy.Index("idx_users_referred_by", users.c.referred_by)
sqlalchemy.Index("idx_wallet_user_network", wallet_addresses.c.user_phone, wallet_addresses.c.network)
sqlalchemy.Index("idx_wallet_address", wallet_addresses.c.address)
sqlalchemy.Index("idx_tx_user_phone", transactions.c.user_phone)
sqlalchemy.Index("idx_tx_type", transactions.c.type)
sqlalchemy.Index("idx_tx_timestamp", transactions.c.timestamp)
sqlalchemy.Index("idx_tx_hash", transactions.c.tx_hash)
sqlalchemy.Index("idx_ledger_user", ledger.c.user_phone)
sqlalchemy.Index("idx_ledger_source", ledger.c.source_type, ledger.c.source_id)
sqlalchemy.Index("idx_deposits_user", processed_deposits.c.user_phone)
sqlalchemy.Index("idx_products_seller", products.c.seller_phone)
sqlalchemy.Index("idx_products_active_category", products.c.is_active, products.c.category)
sqlalchemy.Index("idx_products_price", products.c.price)
sqlalchemy.Index("idx_orders_buyer", orders.c.buyer_phone)
sqlalchemy.Index("idx_orders_seller", orders.c.seller_phone)
sqlalchemy.Index("idx_orders_product", orders.c.product_id)
sqlalchemy.Index("idx_orders_download_token", orders.c.download_token)
sqlalchemy.Index("idx_withdrawals_user_status", withdrawals.c.user_phone, withdrawals.c.status)
sqlalchemy.Index("idx_reviews_product", reviews.c.product_id)
sqlalchemy.Index("idx_otp_phone_purpose", otp_table.c.phone, otp_table.c.purpose)
sqlalchemy.Index("idx_daily_withdraw_phone_date", daily_withdrawals.c.phone, daily_withdrawals.c.date)
sqlalchemy.Index("idx_refresh_token_hash", refresh_tokens.c.token_hash)
sqlalchemy.Index("idx_refresh_phone", refresh_tokens.c.phone)
sqlalchemy.Index("idx_audit_admin", audit_logs.c.admin_phone)
sqlalchemy.Index("idx_audit_target", audit_logs.c.target_phone)
sqlalchemy.Index("idx_chat_receiver", chat_messages.c.receiver_phone)
sqlalchemy.Index("idx_chat_sender", chat_messages.c.sender_phone)

engine = sqlalchemy.create_engine(
    DATABASE_URL.replace("+asyncpg", ""),
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)
metadata.create_all(engine)

create_tables(engine)
app.include_router(chat_router)

# ====== Metrics counter (بسيط - بدون مكتبة خارجية) ======
_metrics = {
    "requests_total": 0,
    "errors_total": 0,
    "db_queries_total": 0,
    "started_at": datetime.utcnow().isoformat(),
}

# ====== Startup / Shutdown ======
@app.on_event("startup")
async def startup():
    await database.connect()
    await database.execute("UPDATE users SET is_admin=1 WHERE phone=:p", {"p": ADMIN_PHONE})
    asyncio.create_task(auto_check_deposits())
    logger.info("تطبيق بدأ | admin=%s", ADMIN_PHONE)

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logger.info("تطبيق أُوقف")

# ====== مساعدات التشفير ======
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt(rounds=12)).decode()

def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except Exception:
        return False

def encrypt_key(k: str) -> str:
    return fernet.encrypt(k.encode()).decode()

def decrypt_key(k: str) -> str:
    return fernet.decrypt(k.encode()).decode()

def hash_token(token: str) -> str:
    """تحويل refresh_token إلى hash قبل تخزينه"""
    return hashlib.sha256(token.encode()).hexdigest()

# ====== JWT ======
def create_token(phone: str, token_version: int) -> str:
    exp = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": phone,
        "exp": exp,
        "iat": datetime.utcnow(),
        "ver": token_version,     # نسخة التوكن - تُبطل عند تغيير كلمة المرور أو الحظر
        "jti": uuid.uuid4().hex,  # معرف فريد للـ JWT
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ====== Refresh Token ======
async def create_refresh_token(phone: str, request: Request = None) -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex  # 64 chars
    token_hash = hash_token(token)
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    ip = request.client.host if request and request.client else None
    ua = request.headers.get("User-Agent", "")[:500] if request else None
    await database.execute(
        """INSERT INTO refresh_tokens (phone,token_hash,expires_at,is_revoked,ip_address,user_agent,created_at)
           VALUES(:p,:th,:e,0,:ip,:ua,:now)""",
        {"p": phone, "th": token_hash, "e": expires, "ip": ip, "ua": ua, "now": datetime.utcnow()}
    )
    return token  # نُرجع القيمة الأصلية للعميل فقط

async def revoke_all_tokens_for_user(phone: str):
    """إبطال جميع refresh tokens عند تغيير كلمة المرور أو الحظر"""
    await database.execute(
        "UPDATE refresh_tokens SET is_revoked=1 WHERE phone=:p AND is_revoked=0",
        {"p": phone}
    )
    # رفع token_version لإبطال جميع access tokens القائمة
    await database.execute(
        "UPDATE users SET token_version=token_version+1 WHERE phone=:p",
        {"p": phone}
    )

# ====== Decimal للأموال ======
def to_decimal(value) -> Decimal:
    """تحويل آمن لأي قيمة إلى Decimal"""
    try:
        return Decimal(str(value)).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
    except (InvalidOperation, TypeError, ValueError):
        raise HTTPException(400, "قيمة مالية غير صالحة")

def validate_positive_amount(amount) -> Decimal:
    d = to_decimal(amount)
    if d <= 0:
        raise HTTPException(400, "المبلغ يجب أن يكون أكبر من صفر")
    return d

# ====== Ledger ======
async def write_ledger(
    phone: str,
    entry_type: str,
    amount: Decimal,
    balance_before: Decimal,
    balance_after: Decimal,
    source_type: str,
    source_id: str,
    description: str,
):
    """تسجيل كل حركة مالية في دفتر الحسابات"""
    await database.execute(
        """INSERT INTO ledger (user_phone,entry_type,amount,balance_before,balance_after,source_type,source_id,description,created_at)
           VALUES(:p,:et,:a,:bb,:ba,:st,:sid,:d,:now)""",
        {
            "p": phone, "et": entry_type, "a": float(amount),
            "bb": float(balance_before), "ba": float(balance_after),
            "st": source_type, "sid": source_id, "d": description, "now": datetime.utcnow()
        }
    )

# ====== Ledger-aasync def debit_balance(phone: str, amount: Decimal, source_type: str, source_id: str, description: str):
async def debit_balance(phone: str, amount: Decimal, source_type: str, source_id: str, description: str) -> Decimal:
    """خصم ذري من الرصيد مع تسجيل في Ledger"""
    row = await database.fetch_one(
        "UPDATE users SET balance=balance-:a WHERE phone=:p AND balance>=:a RETURNING balance",
        {"a": float(amount), "p": phone}
    )

    if row is None:
        raise HTTPException(400, "الرصيد غير كافٍ")

    new_balance = to_decimal(row["balance"])
    old_balance = new_balance + amount

    await write_ledger(
        phone, "debit", amount, old_balance, new_balance,
        source_type, source_id, description
    )
    return new_balance
   

# ====== مساعدات عامة ======
def generate_tron_wallet():
    pk = PrivateKey.random()
    return pk.public_key.to_base58check_address(), pk.hex()

def generate_referral_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def generate_download_token():
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 chars

def calc_platform_fee(amount: Decimal) -> Decimal:
    return (amount * Decimal(str(PLATFORM_FEE_PERCENT)) / Decimal("100")).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)

def calc_withdraw_fee(amount: Decimal) -> Decimal:
    return to_decimal(WITHDRAW_FEE_FIXED)

async def add_platform_earning(amount: Decimal, description: str):
    await database.execute(
        "INSERT INTO platform_account (type,amount,description,timestamp) VALUES('fee',:a,:d,:t)",
        {"a": float(amount), "d": description, "t": datetime.utcnow()}
    )

async def get_daily_withdrawn(phone: str) -> Decimal:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    row = await database.fetch_one(
        "SELECT COALESCE(SUM(amount),0) as total FROM daily_withdrawals WHERE phone=:p AND date=:d",
        {"p": phone, "d": today}
    )
    return to_decimal(row["total"]) if row else Decimal("0")

# ====== OTP - مُخزن كـ Hash ======
async def create_otp(phone: str, purpose: str) -> str:
    otp = ''.join(random.choices(string.digits, k=6))
    otp_hash = hashlib.sha256(otp.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    # إلغاء أي OTP سابق غير مستخدم
    await database.execute(
        "UPDATE otp_codes SET used=1 WHERE phone=:p AND purpose=:pu AND used=0",
        {"p": phone, "pu": purpose}
    )
    await database.execute(
        "INSERT INTO otp_codes (phone,code_hash,purpose,used,attempts,expires_at,created_at) VALUES(:p,:c,:pu,0,0,:e,:t)",
        {"p": phone, "c": otp_hash, "pu": purpose, "e": expires, "t": datetime.utcnow()}
    )
    return otp  # القيمة الأصلية تُرسل عبر Telegram فقط

async def verify_otp(phone: str, code: str, purpose: str) -> bool:
    """التحقق من OTP مع حماية من Brute Force"""
    row = await database.fetch_one(
        "SELECT * FROM otp_codes WHERE phone=:p AND purpose=:pu AND used=0 AND expires_at > :now ORDER BY created_at DESC LIMIT 1",
        {"p": phone, "pu": purpose, "now": datetime.utcnow()}
    )
    if not row:
        return False

    # حماية Brute Force: قفل بعد OTP_MAX_ATTEMPTS محاولة خاطئة
    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        await database.execute("UPDATE otp_codes SET used=1 WHERE id=:i", {"i": row["id"]})
        raise HTTPException(429, f"تجاوزت الحد المسموح من المحاولات ({OTP_MAX_ATTEMPTS}). أعد طلب OTP جديد.")

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if not hmac.compare_digest(code_hash, row["code_hash"]):
        await database.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE id=:i", {"i": row["id"]})
        remaining = OTP_MAX_ATTEMPTS - row["attempts"] - 1
        if remaining <= 0:
            await database.execute("UPDATE otp_codes SET used=1 WHERE id=:i", {"i": row["id"]})
            raise HTTPException(429, "تم قفل OTP لتجاوز عدد المحاولات. أعد الطلب.")
        return False

    await database.execute("UPDATE otp_codes SET used=1 WHERE id=:i", {"i": row["id"]})
    return True

# ====== Telegram ======
async def send_otp_telegram(chat_id: str, otp: str, purpose: str):
    if not chat_id or not TELEGRAM_BOT_TOKEN:
        logger.warning("send_otp_telegram: بيانات ناقصة chat_id=%s", chat_id)
        return
    msg = f"🔐 رمز التحقق الخاص بك\n\n*{otp}*\n\nصالح لمدة {OTP_EXPIRE_MINUTES} دقائق\nلا تشاركه مع أحد ⚠️"
    try:
        async with httpx.AsyncClient(timeout=10) as client_http:
            await client_http.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"}
            )
    except Exception as e:
        logger.error("send_otp_telegram خطأ: %s", e)

async def notify_telegram(chat_id: str, message: str):
    if not chat_id or not TELEGRAM_BOT_TOKEN:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as client_http:
            await client_http.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
            )
    except Exception as e:
        logger.warning("notify_telegram خطأ: %s", e)

# ====== التحقق من عنوان TRON ======
def is_valid_tron_address(address: str) -> bool:
    if not address:
        return False
    # عنوان TRON: يبدأ بـ T، 34 حرف
    if not re.match(r'^T[A-Za-z0-9]{33}$', address):
        return False
    try:
        from tronpy.keys import to_hex_address
        to_hex_address(address)
        return True
    except Exception:
        return False

# ====== MIME Validation ======
MAGIC_BYTES = {
    b"\xff\xd8\xff": "image",
    b"\x89PNG\r\n\x1a\n": "image",
    b"GIF87a": "image",
    b"GIF89a": "image",
    b"RIFF": "image",
    b"%PDF": "document",
    b"PK\x03\x04": "archive",
    b"\x1f\x8b": "archive",
    b"Rar!": "archive",
    b"ID3": "audio",
    b"fLaC": "audio",
    b"OggS": "audio",
}

DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "php", "php3", "php4", "php5", "phtml",
    "py", "rb", "pl", "js", "ts", "asp", "aspx", "jsp", "cgi",
    "htaccess", "htpasswd", "dll", "so", "dylib", "com", "msi",
    "vbs", "ps1", "psd1", "psm1", "scr", "hta", "jar", "war",
}

def get_file_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    for ftype, exts in ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return ftype
    return "other"

def validate_file_mime(content: bytes, declared_ext: str) -> bool:
    ext = declared_ext.lower()
    if ext in DANGEROUS_EXTENSIONS:
        return False
    # تحقق من null bytes (مؤشر اختراق)
    if b"\x00" in content[:20] and ext not in ["zip", "rar", "pdf", "doc", "docx", "xlsx"]:
        pass  # بعض الأنواع طبيعية
    for magic, ftype in MAGIC_BYTES.items():
        if content.startswith(magic):
            allowed_exts_for_type = ALLOWED_EXTENSIONS.get(ftype, [])
            if ftype == "archive" and ext in ["docx", "xlsx", "xls", "doc"]:
                return True
            if ext in allowed_exts_for_type:
                return True
            return False
    if ext == "txt":
        try:
            content[:1024].decode("utf-8")
            return True
        except Exception:
            return False
    return True

def sanitize_filename(filename: str) -> str:
    """تنظيف اسم الملف من مسارات خطرة"""
    # منع Path Traversal
    name = os.path.basename(filename)
    # إزالة الأحرف الخطرة
    name = re.sub(r'[^\w\s.\-]', '_', name)
    # منع ملفات hidden files
    name = name.lstrip('.')
    return name or "file"

async def save_upload_file(upload_file: UploadFile, folder: str) -> tuple:
    """حفظ ملف مرفوع مع جميع فحوصات الأمان"""
    original_name = sanitize_filename(upload_file.filename or "file")
    ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else "bin"

    if ext in DANGEROUS_EXTENSIONS:
        raise HTTPException(400, f"نوع الملف غير مسموح: .{ext}")

    all_allowed = set()
    for exts in ALLOWED_EXTENSIONS.values():
        all_allowed.update(exts)
    if ext not in all_allowed:
        raise HTTPException(400, f"امتداد الملف غير مسموح: .{ext}")

    content = await upload_file.read()

    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise HTTPException(400, f"حجم الملف يتجاوز {MAX_FILE_SIZE_MB}MB")

    if not validate_file_mime(content, ext):
        raise HTTPException(400, f"محتوى الملف لا يتوافق مع امتداده (.{ext})")

    # اسم فريد عشوائي - منع overwrite
    unique_name = f"{uuid.uuid4().hex}.{ext}"

    # التحقق من أن المسار داخل المجلد المسموح فقط (Path Traversal Protection)
    base_dir = Path(UPLOAD_DIR) / folder
    save_path = base_dir / unique_name
    if not str(save_path.resolve()).startswith(str(base_dir.resolve())):
        raise HTTPException(400, "مسار غير صالح")

    base_dir.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(save_path, "wb") as f:
        await f.write(content)

    file_url = f"/uploads/{folder}/{unique_name}"
    file_type = get_file_type(original_name)
    return file_url, original_name, file_type, len(content)

# ====== Auth Dependencies ======
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

async def audit(admin_phone: str, action: str, target_phone: str = None,
                target_id: str = None, details: str = None, request: Request = None):
    ip = request.client.host if request and request.client else None
    await database.execute(
        """INSERT INTO audit_logs (admin_phone,action,target_phone,target_id,details,ip_address,created_at)
           VALUES(:a,:ac,:t,:tid,:d,:ip,:now)""",
        {"a": admin_phone, "ac": action, "t": target_phone, "tid": target_id,
         "d": details, "ip": ip, "now": datetime.utcnow()}
    )

# ====== Tron ======
def send_usdt_tron(to_address: str, amount: Decimal) -> str:
    contract = client.get_contract(NETWORKS["TRC20"]["usdt_contract"])
    amount_sun = int(amount * Decimal("1000000"))
    txn = (
        contract.functions.transfer(to_address, amount_sun)
        .with_owner(HOT_WALLET_ADDRESS)
        .fee_limit(10_000_000)
        .build()
        .sign(PrivateKey(bytes.fromhex(HOT_WALLET_KEY)))
        .broadcast()
    )
    tx_hash = txn.get("txid", "")
    if not tx_hash:
        raise Exception("فشل في إرسال المعاملة - لم يُستلم tx_hash")
    return tx_hash

async def check_usdt_deposit(address: str, user_phone: str) -> Decimal:
    try:
        async with httpx.AsyncClient(timeout=30) as client_http:
            res = await client_http.get(
                f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20",
                headers={"TRON-PRO-API-KEY": TRON_API_KEY},
                params={"limit": 20, "contract_address": NETWORKS["TRC20"]["usdt_contract"]}
            )
        new_total = Decimal("0")
        for tx in res.json().get("data", []):
            tx_hash = tx.get("transaction_id")
            if not tx_hash or tx["to"] != address:
                continue

            existing = await database.fetch_one(
                "SELECT status FROM processed_deposits WHERE tx_hash=:h", {"h": tx_hash}
            )
            if existing and existing["status"] == "confirmed":
                continue

            amount = to_decimal(int(tx["value"]) / 1_000_000)
            try:
                info = client.get_transaction_info(tx_hash)
                confs = client.get_latest_block_number() - info.get("blockNumber", 0)
            except Exception:
                confs = 0

            if confs >= MIN_CONFIRMATIONS:
                async with database.transaction():
                    if not existing:
                        # INSERT OR IGNORE - منع Double Deposit
                        await database.execute(
                            """INSERT INTO processed_deposits (tx_hash,user_phone,amount,confirmations,status,network,timestamp)
                               VALUES(:h,:p,:a,:c,'confirmed','TRC20',:t)
                               ON CONFLICT (tx_hash) DO NOTHING""",
                            {"h": tx_hash, "p": user_phone, "a": float(amount), "c": confs, "t": datetime.utcnow()}
                        )
                        # التحقق أن الإدراج نجح (وليس تكراراً)
                        check = await database.fetch_one(
                            "SELECT user_phone FROM processed_deposits WHERE tx_hash=:h AND status='confirmed'",
                            {"h": tx_hash}
                        )
                        if check and check["user_phone"] == user_phone:
                            await database.execute(
                                """INSERT INTO transactions (user_phone,type,amount,fee,status,description,tx_hash,network,timestamp)
                                   VALUES(:p,'deposit',:a,0,'completed','إيداع USDT TRC20',:h,'TRC20',:t)
                                   ON CONFLICT (tx_hash) DO NOTHING""",
                                {"p": user_phone, "a": float(amount), "h": tx_hash, "t": datetime.utcnow()}
                            )
                            # تحديث الرصيد مع Ledger
                            await credit_balance(
                                user_phone, amount, "deposit", tx_hash,
                                f"إيداع USDT TRC20 - {tx_hash[:16]}..."
                            )
                            new_total += amount
                            logger.info("إيداع جديد user=%s amount=%s tx=%s", user_phone, amount, tx_hash)
                    else:
                        await database.execute(
                            "UPDATE processed_deposits SET status='confirmed', confirmations=:c WHERE tx_hash=:h",
                            {"c": confs, "h": tx_hash}
                        )
            elif not existing:
                await database.execute(
                    """INSERT INTO processed_deposits (tx_hash,user_phone,amount,confirmations,status,network,timestamp)
                       VALUES(:h,:p,:a,:c,'pending','TRC20',:t)
                       ON CONFLICT (tx_hash) DO NOTHING""",
                    {"h": tx_hash, "p": user_phone, "a": float(amount), "c": confs, "t": datetime.utcnow()}
                )
        return new_total
    except Exception as e:
        logger.error("check_usdt_deposit خطأ user=%s: %s", user_phone, e)
        return Decimal("0")

async def wait_for_tron_confirmation(tx_hash: str, max_wait_seconds: int = 120) -> bool:
    for _ in range(max_wait_seconds // 5):
        try:
            info = client.get_transaction_info(tx_hash)
            if info.get("blockNumber"):
                confs = client.get_latest_block_number() - info["blockNumber"]
                if confs >= 3:
                    return True
        except Exception:
            pass
        await asyncio.sleep(5)
    return False

async def sweep_wallet(user_phone: str, address: str, private_key_enc: str):
    try:
        contract = client.get_contract(NETWORKS["TRC20"]["usdt_contract"])
        balance_sun = contract.functions.balanceOf(address)
        if balance_sun < 1_000_000:
            return None
        amount_usdt = to_decimal(balance_sun / 1_000_000)
        pk_hex = decrypt_key(private_key_enc)
        pk = PrivateKey(bytes.fromhex(pk_hex))

        trx_balance = client.get_account_balance(address)
        if trx_balance < 5:
            fee_txn = (
                client.trx.transfer(address, int(6 * 1_000_000))
                .with_owner(HOT_WALLET_ADDRESS)
                .fee_limit(5_000_000)
                .build()
                .sign(PrivateKey(bytes.fromhex(HOT_WALLET_KEY)))
                .broadcast()
            )
            fee_tx_hash = fee_txn.get("txid", "")
            confirmed = await wait_for_tron_confirmation(fee_tx_hash, max_wait_seconds=120)
            if not confirmed:
                logger.warning("sweep_wallet: TRX لم يُؤكد user=%s", user_phone)
                return None

        txn = (
            contract.functions.transfer(HOT_WALLET_ADDRESS, balance_sun)
            .with_owner(address)
            .fee_limit(10_000_000)
            .build()
            .sign(pk)
            .broadcast()
        )
        tx_hash = txn.get("txid", "")
        if tx_hash:
            await database.execute(
                """INSERT INTO transactions (user_phone,type,amount,fee,status,description,tx_hash,network,timestamp)
                   VALUES(:p,'sweep',:a,0,'completed','نقل تلقائي إلى Hot Wallet',:h,'TRC20',:t)
                   ON CONFLICT (tx_hash) DO NOTHING""",
                {"p": user_phone, "a": float(amount_usdt), "h": tx_hash, "t": datetime.utcnow()}
            )
            logger.info("sweep_wallet: نجح user=%s amount=%s tx=%s", user_phone, amount_usdt, tx_hash)
        return tx_hash
    except Exception as e:
        logger.error("sweep_wallet خطأ user=%s: %s", user_phone, e)
        return None

async def auto_check_deposits():
    while True:
        await asyncio.sleep(300)
        try:
            all_wallets = await database.fetch_all(
                "SELECT user_phone, address, private_key_enc FROM wallet_addresses WHERE network='TRC20'"
            )
            for w in all_wallets:
                new_amount = await check_usdt_deposit(w["address"], w["user_phone"])
                if new_amount > 0:
                    await sweep_wallet(w["user_phone"], w["address"], w["private_key_enc"])
        except Exception as e:
            logger.error("auto_check_deposits خطأ: %s", e)

# ====== Pydantic Models ======
class UserRegister(BaseModel):
    phone: str
    name: str
    email: str
    password: str
    referral_code: Optional[str] = None

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        if not re.match(r'^\+?[0-9]{7,15}$', v):
            raise ValueError("رقم الهاتف غير صالح")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("كلمة المرور يجب أن تكون 8 أحرف على الأقل")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if len(v.strip()) < 2:
            raise ValueError("الاسم قصير جداً")
        return v.strip()

class Transfer(BaseModel):
    receiver_phone: str
    amount: float
    note: str = ""

    @field_validator("note")
    @classmethod
    def sanitize_note(cls, v):
        return v[:200].strip() if v else ""

class WithdrawRequest(BaseModel):
    to_address: str
    amount: float
    network: str = "TRC20"

class WithdrawConfirm(BaseModel):
    to_address: str
    amount: float
    network: str = "TRC20"
    otp: str

class LinkTelegram(BaseModel):
    telegram_chat_id: str

    @field_validator("telegram_chat_id")
    @classmethod
    def validate_chat_id(cls, v):
        if not re.match(r'^-?[0-9]+$', v):
            raise ValueError("chat_id غير صالح")
        return v

class ChangePassword(BaseModel):
    old_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError("كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل")
        return v

class BuyProduct(BaseModel):
    product_id: int

class AdjustBalance(BaseModel):
    phone: str
    amount: float
    note: str = ""

class SendMessage(BaseModel):
    message: str
    receiver_phone: Optional[str] = None

    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        if not v or not v.strip():
            raise ValueError("الرسالة لا يمكن أن تكون فارغة")
        return v.strip()[:2000]

class SellerRequestModel(BaseModel):
    shop_name: str
    shop_description: str
    product_types: str
    is_digital: bool = True
    extra_info: Optional[str] = None

    @field_validator("shop_name")
    @classmethod
    def validate_shop_name(cls, v):
        if len(v.strip()) < 3:
            raise ValueError("اسم المتجر قصير جداً")
        return v.strip()[:100]

class ReviewModel(BaseModel):
    order_id: int
    product_id: int
    rating: int
    comment: Optional[str] = None

    @field_validator("rating")
    @classmethod
    def validate_rating(cls, v):
        if v < 1 or v > 5:
            raise ValueError("التقييم يجب أن يكون بين 1 و5")
        return v

    @field_validator("comment")
    @classmethod
    def sanitize_comment(cls, v):
        return v.strip()[:1000] if v else None

class ApproveSellerModel(BaseModel):
    phone: str
    approved: bool
    admin_note: Optional[str] = None

class AdminReplyModel(BaseModel):
    receiver_phone: str
    message: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# ====== Health / Readiness / Metrics ======
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/readiness")
async def readiness():
    try:
        await database.fetch_one("SELECT 1")
        db_ok = True
    except Exception as e:
        logger.error("readiness DB خطأ: %s", e)
        db_ok = False
    status = "ok" if db_ok else "degraded"
    code = 200 if db_ok else 503
    return JSONResponse(
        {"status": status, "database": "ok" if db_ok else "error", "timestamp": datetime.utcnow().isoformat()},
        status_code=code
    )

@app.get("/metrics")
async def metrics(admin=Depends(require_admin)):
    users_count = await database.fetch_one("SELECT COUNT(*) as cnt FROM users")
    balance_total = await database.fetch_one("SELECT COALESCE(SUM(balance),0) as total FROM users")
    pending_deposits = await database.fetch_one("SELECT COUNT(*) as cnt FROM processed_deposits WHERE status='pending'")
    pending_withdrawals = await database.fetch_one("SELECT COUNT(*) as cnt FROM withdrawals WHERE status='pending'")
    return {
        "requests_total": _metrics["requests_total"],
        "errors_total": _metrics["errors_total"],
        "started_at": _metrics["started_at"],
        "uptime_seconds": (datetime.utcnow() - datetime.fromisoformat(_metrics["started_at"])).total_seconds(),
        "total_users": users_count["cnt"],
        "total_balance_usd": float(balance_total["total"]),
        "pending_deposits": pending_deposits["cnt"],
        "pending_withdrawals": pending_withdrawals["cnt"],
    }

# ====== Routes: Auth ======
@app.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, data: UserRegister):
    if await database.fetch_one("SELECT phone FROM users WHERE phone=:p", {"p": data.phone}):
        return {"success": False, "message": "الحساب موجود مسبقاً"}

    referral_code = generate_referral_code()
    referred_by = None
    if data.referral_code:
        referrer = await database.fetch_one(
            "SELECT phone FROM users WHERE referral_code=:c", {"c": data.referral_code}
        )
        if referrer:
            referred_by = referrer["phone"]

    is_admin = 1 if data.phone == ADMIN_PHONE else 0
    async with database.transaction():
        await database.execute(
            """INSERT INTO users (phone,name,email,password,balance,is_admin,is_banned,is_seller,seller_approved,
               referral_code,referred_by,token_version,created_at)
               VALUES(:ph,:n,:e,:pw,0,:ad,0,0,0,:rc,:rb,0,:t)""",
            {"ph": data.phone, "n": data.name, "e": data.email,
             "pw": hash_password(data.password), "ad": is_admin,
             "rc": referral_code, "rb": referred_by, "t": datetime.utcnow()}
        )
        address, pk = generate_tron_wallet()
        await database.execute(
            "INSERT INTO wallet_addresses (user_phone,network,address,private_key_enc) VALUES(:p,'TRC20',:a,:k)",
            {"p": data.phone, "a": address, "k": encrypt_key(pk)}
        )

    logger.info("تسجيل مستخدم جديد: %s", data.phone)
    return {
        "success": True,
        "message": "تم التسجيل بنجاح 🎉",
        "trc20_address": address,
        "referral_code": referral_code
    }

@app.post("/token")
@limiter.limit("10/minute")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    user = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": form.username})
    if not user or not verify_password(form.password, user["password"]):
        logger.warning("محاولة تسجيل دخول فاشلة: %s", form.username)
        raise HTTPException(401, "بيانات خاطئة")
    if user["is_banned"]:
        raise HTTPException(403, "الحساب محظور")

    refresh_token = await create_refresh_token(user["phone"], request)
    access_token = create_token(user["phone"], user["token_version"])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_HOURS * 3600,
        "name": user["name"],
        "balance": float(user["balance"]),
        "is_seller": bool(user["is_seller"] and user["seller_approved"]),
        "is_admin": bool(user["is_admin"]),
        "referral_code": user["referral_code"]
    }

@app.post("/token/refresh")
@limiter.limit("20/minute")
async def refresh_access_token(request: Request, data: RefreshTokenRequest):
    token_hash = hash_token(data.refresh_token)
    row = await database.fetch_one(
        "SELECT * FROM refresh_tokens WHERE token_hash=:th AND is_revoked=0 AND expires_at > :now",
        {"th": token_hash, "now": datetime.utcnow()}
    )
    if not row:
        raise HTTPException(401, "refresh_token منتهي أو غير صالح")

    user = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": row["phone"]})
    if not user or user["is_banned"]:
        raise HTTPException(403, "الحساب محظور أو غير موجود")

    return {
        "access_token": create_token(user["phone"], user["token_version"]),
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_HOURS * 3600
    }

@app.post("/token/revoke")
async def revoke_token(data: RefreshTokenRequest, user=Depends(get_current_user)):
    token_hash = hash_token(data.refresh_token)
    await database.execute(
        "UPDATE refresh_tokens SET is_revoked=1 WHERE token_hash=:th AND phone=:p",
        {"th": token_hash, "p": user["phone"]}
    )
    return {"success": True, "message": "تم تسجيل الخروج"}

@app.post("/link-telegram")
async def link_telegram(data: LinkTelegram, user=Depends(get_current_user)):
    await database.execute(
        "UPDATE users SET telegram_chat_id=:t WHERE phone=:p",
        {"t": data.telegram_chat_id, "p": user["phone"]}
    )
    await notify_telegram(
        data.telegram_chat_id,
        f"✅ تم ربط حسابك بنجاح!\nمرحباً {user['name']} 👋\nستصلك رموز OTP هنا عند السحب."
    )
    return {"success": True, "message": "تم ربط التيليجرام"}

@app.get("/me")
async def me(user=Depends(get_current_user)):
    wallets = await database.fetch_all(
        "SELECT network, address FROM wallet_addresses WHERE user_phone=:p", {"p": user["phone"]}
    )
    unread = await database.fetch_one(
        "SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_phone=:p AND is_read=0",
        {"p": user["phone"]}
    )
    return {
        "phone": user["phone"],
        "name": user["name"],
        "email": user["email"],
        "balance": float(user["balance"]),
        "avatar_url": user["avatar_url"],
        "referral_code": user["referral_code"],
        "telegram_linked": bool(user["telegram_chat_id"]),
        "is_seller": bool(user["is_seller"] and user["seller_approved"]),
        "seller_pending": bool(user["is_seller"] and not user["seller_approved"]),
        "shop_name": user["shop_name"],
        "wallets": [dict(w) for w in wallets],
        "unread_messages": unread["cnt"] if unread else 0,
    }

@app.post("/change-password")
async def change_password(data: ChangePassword, user=Depends(get_current_user)):
    if not verify_password(data.old_password, user["password"]):
        return {"success": False, "message": "كلمة المرور الحالية خاطئة"}
    async with database.transaction():
        await database.execute(
            "UPDATE users SET password=:pw WHERE phone=:p",
            {"pw": hash_password(data.new_password), "p": user["phone"]}
        )
        # إبطال جميع الجلسات القائمة
        await revoke_all_tokens_for_user(user["phone"])
    logger.info("تغيير كلمة مرور: %s", user["phone"])
    return {"success": True, "message": "تم تغيير كلمة المرور. يرجى تسجيل الدخول مجدداً."}

@app.post("/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), user=Depends(get_current_user)):
    ftype = get_file_type(file.filename or "")
    if ftype != "image":
        return {"success": False, "message": "يجب أن يكون ملف صورة"}
    url, _, _, _ = await save_upload_file(file, "avatars")
    await database.execute("UPDATE users SET avatar_url=:u WHERE phone=:p", {"u": url, "p": user["phone"]})
    return {"success": True, "avatar_url": url}

# ====== Routes: Wallet ======
@app.get("/check-receiver/{phone}")
async def check_receiver(phone: str, user=Depends(get_current_user)):
    r = await database.fetch_one("SELECT name,phone FROM users WHERE phone=:p", {"p": phone})
    if not r:
        return {"success": False, "message": "المستخدم غير موجود"}
    return {"success": True, "name": r["name"], "phone": r["phone"]}

@app.post("/transfer")
@limiter.limit("20/minute")
async def transfer(request: Request, data: Transfer, user=Depends(get_current_user)):
    amount = validate_positive_amount(data.amount)
    if user["phone"] == data.receiver_phone:
        return {"success": False, "message": "لا يمكن التحويل لنفسك"}

    fee = (amount * Decimal(str(TRANSFER_FEE_PERCENT)) / Decimal("100")).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
    receiver_amount = (amount - fee).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)

    receiver = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": data.receiver_phone})
    if not receiver:
        return {"success": False, "message": "المستلم غير موجود"}
    if receiver["is_banned"]:
        return {"success": False, "message": "لا يمكن التحويل لهذا الحساب"}

    now = datetime.utcnow()
    ref_id = uuid.uuid4().hex


    async with database.transaction():
        row = await database.fetch_one(
            "UPDATE users SET balance=balance-:a WHERE phone=:p AND balance>=:a RETURNING balance",
            {"a": float(amount), "p": user["phone"]}
        )

        if row is None:
            raise HTTPException(400, "الرصيد غير كافٍ")

        # إضافة للمستلم
        await database.execute(
            "UPDATE users SET balance=balance+:a WHERE phone=:p",
            {"a": float(receiver_amount), "p": data.receiver_phone}
        )
        await add_platform_earning(fee, f"عمولة تحويل من {user['phone']}")

        # تسجيل المعاملات
        await database.execute(
            """INSERT INTO transactions (user_phone,type,amount,fee,status,related_phone,description,ref_id,timestamp)
               VALUES(:p,'transfer_sent',:a,:f,'completed',:r,:d,:ref,:t)""",
            {"p": user["phone"], "a": float(amount), "f": float(fee),
             "r": data.receiver_phone, "d": f"تحويل إلى {receiver['name']} - {data.note}", "ref": ref_id, "t": now}
        )
        await database.execute(
            """INSERT INTO transactions (user_phone,type,amount,fee,status,related_phone,description,ref_id,timestamp)
               VALUES(:p,'transfer_received',:a,0,'completed',:r,:d,:ref,:t)""",
            {"p": data.receiver_phone, "a": float(receiver_amount),
             "r": user["phone"], "d": f"استلام من {user['name']} - {data.note}", "ref": ref_id, "t": now}
        )

        sender_user = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": user["phone"]})
        receiver_user = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": data.receiver_phone})
        sender_balance_after = to_decimal(sender_user["balance"])
        receiver_balance_after = to_decimal(receiver_user["balance"])

        await write_ledger(user["phone"], "debit", amount,
                           sender_balance_after + amount, sender_balance_after,
                           "transfer", ref_id, f"تحويل إلى {receiver['name']}")
        await write_ledger(data.receiver_phone, "credit", receiver_amount,
                           receiver_balance_after - receiver_amount, receiver_balance_after,
                           "transfer", ref_id, f"استلام من {user['name']}")

    # مكافأة الإحالة خارج الـ transaction الرئيسية
    if user["referred_by"] and REFERRAL_BONUS_PERCENT > 0:
        bonus = (amount * Decimal(str(REFERRAL_BONUS_PERCENT)) / Decimal("100")).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
        if bonus > 0:
            await credit_balance(user["referred_by"], bonus, "referral_bonus", ref_id, f"مكافأة إحالة من {user['phone']}")

    await notify_telegram(
        receiver["telegram_chat_id"],
        f"💸 استلمت تحويلاً جديداً\n\nالمبلغ: *{receiver_amount} USDT*\nمن: {user['name']}\nملاحظة: {data.note}"
    )
    return {"success": True, "sent": float(amount), "fee": float(fee), "receiver_got": float(receiver_amount), "receiver": receiver["name"]}

@app.post("/withdraw/request")
@limiter.limit("5/minute")
async def withdraw_request(request: Request, data: WithdrawRequest, user=Depends(get_current_user)):
    if not is_valid_tron_address(data.to_address):
        return {"success": False, "message": "عنوان TRON غير صالح"}
    amount = validate_positive_amount(data.amount)
    if amount < Decimal(str(MIN_WITHDRAW)):
        return {"success": False, "message": f"الحد الأدنى {MIN_WITHDRAW} USDT"}
    if to_decimal(user["balance"]) < amount:
        return {"success": False, "message": "الرصيد غير كافٍ"}
    today_total = await get_daily_withdrawn(user["phone"])
    if today_total + amount > Decimal(str(MAX_DAILY_WITHDRAW)):
        remaining = Decimal(str(MAX_DAILY_WITHDRAW)) - today_total
        return {"success": False, "message": f"تجاوزت الحد اليومي. المتبقي: {remaining:.2f} USDT"}
    if not user["telegram_chat_id"]:
        return {"success": False, "message": "يجب ربط حساب تيليجرام أولاً لاستقبال OTP"}

    otp = await create_otp(user["phone"], "withdraw")
    await send_otp_telegram(user["telegram_chat_id"], otp, "withdraw")
    fee = calc_withdraw_fee(amount)
    return {
        "success": True,
        "message": "تم إرسال رمز OTP على تيليجرام",
        "amount": float(amount),
        "fee": float(fee),
        "you_receive": float(amount - fee),
        "otp_expires_minutes": OTP_EXPIRE_MINUTES
    }

@app.post("/withdraw/confirm")
@limiter.limit("5/minute")
async def withdraw_confirm(request: Request, data: WithdrawConfirm, user=Depends(get_current_user)):
    if not is_valid_tron_address(data.to_address):
        return {"success": False, "message": "عنوان TRON غير صالح"}

    # التحقق من OTP أولاً
    otp_valid = await verify_otp(user["phone"], data.otp, "withdraw")
    if not otp_valid:
        return {"success": False, "message": "رمز OTP خاطئ أو منتهي"}

    amount = validate_positive_amount(data.amount)
    if amount < Decimal(str(MIN_WITHDRAW)):
        return {"success": False, "message": f"الحد الأدنى {MIN_WITHDRAW} USDT"}

    today_total = await get_daily_withdrawn(user["phone"])
    if today_total + amount > Decimal(str(MAX_DAILY_WITHDRAW)):
        return {"success": False, "message": "تجاوزت الحد اليومي"}

    fee = calc_withdraw_fee(amount)
    send_amount = (amount - fee).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)

    now = datetime.utcnow()
    today = now.strftime("%Y-%m-%d")

    # إنشاء سجل السحب بحالة pending أولاً
    withdrawal_id = await database.execute(
        """INSERT INTO withdrawals (user_phone,to_address,amount,fee,net_amount,network,status,otp_verified_at,created_at)
           VALUES(:p,:a,:am,:f,:na,'TRC20','processing',:ov,:t)""",
        {"p": user["phone"], "a": data.to_address, "am": float(amount),
         "f": float(fee), "na": float(send_amount), "ov": now, "t": now}
    )

    try:
        async with database.transaction():
            # خصم ذري - منع Double Withdrawal
            result = await database.execute(
                "UPDATE users SET balance=balance-:a WHERE phone=:p AND balance>=:a",
                {"a": float(amount), "p": user["phone"]}
            )
            if result == 0:
                await database.execute(
                    "UPDATE withdrawals SET status='failed',failed_reason='رصيد غير كافٍ' WHERE id=:i",
                    {"i": withdrawal_id}
                )
                raise HTTPException(400, "الرصيد غير كافٍ")

            # إرسال على الشبكة
            tx_hash = send_usdt_tron(data.to_address, send_amount)

            await add_platform_earning(fee, f"عمولة سحب من {user['phone']}")
            await database.execute(
                """INSERT INTO transactions (user_phone,type,amount,fee,status,description,tx_hash,network,timestamp)
                   VALUES(:p,'withdraw',:a,:f,'completed',:d,:h,'TRC20',:t)""",
                {"p": user["phone"], "a": float(amount), "f": float(fee),
                 "d": f"سحب إلى {data.to_address}", "h": tx_hash, "t": now}
            )
            await database.execute(
                "INSERT INTO daily_withdrawals (phone,amount,date) VALUES(:p,:a,:d)",
                {"p": user["phone"], "a": float(amount), "d": today}
            )

            # Ledger
            user_row = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": user["phone"]})
            balance_after = to_decimal(user_row["balance"])
            await write_ledger(user["phone"], "debit", amount,
                               balance_after + amount, balance_after,
                               "withdraw", tx_hash, f"سحب إلى {data.to_address}")

            # تحديث حالة السحب
            await database.execute(
                "UPDATE withdrawals SET status='completed',tx_hash=:h,completed_at=:ca WHERE id=:i",
                {"h": tx_hash, "ca": now, "i": withdrawal_id}
            )

        logger.info("سحب ناجح: user=%s amount=%s tx=%s", user["phone"], amount, tx_hash)
        return {"success": True, "message": "تم السحب بنجاح ✅", "tx_hash": tx_hash,
                "sent": float(send_amount), "fee": float(fee)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("withdraw_confirm خطأ user=%s: %s", user["phone"], e)
        await database.execute(
            "UPDATE withdrawals SET status='failed',failed_reason=:r WHERE id=:i",
            {"r": str(e)[:400], "i": withdrawal_id}
        )
        return {"success": False, "message": "فشل السحب. تواصل مع الدعم إذا خُصم الرصيد."}

@app.post("/check-deposit")
async def check_deposit(user=Depends(get_current_user)):
    wallet = await database.fetch_one(
        "SELECT address FROM wallet_addresses WHERE user_phone=:p AND network='TRC20'", {"p": user["phone"]}
    )
    if not wallet:
        return {"success": False, "message": "لا توجد محفظة"}
    new_amount = await check_usdt_deposit(wallet["address"], user["phone"])
    updated = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": user["phone"]})

    # مكافأة الإحالة
    if new_amount > 0 and user["referred_by"] and REFERRAL_BONUS_PERCENT > 0:
        bonus = (new_amount * Decimal(str(REFERRAL_BONUS_PERCENT)) / Decimal("100")).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
        if bonus > 0:
            await credit_balance(user["referred_by"], bonus, "referral_bonus",
                                  f"deposit_{user['phone']}", f"مكافأة إحالة - إيداع {user['phone']}")

    return {"success": True, "new_deposit": float(new_amount), "balance": float(updated["balance"])}

@app.get("/transactions")
async def get_transactions(
    user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    tx_type: Optional[str] = None,
):
    offset = (page - 1) * limit
    query = "SELECT type,amount,fee,status,timestamp,description,tx_hash,related_phone FROM transactions WHERE user_phone=:p"
    params = {"p": user["phone"]}
    if tx_type:
        query += " AND type=:t"
        params["t"] = tx_type
    count_query = f"SELECT COUNT(*) as cnt FROM transactions WHERE user_phone=:p" + (" AND type=:t" if tx_type else "")
    total = await database.fetch_one(count_query, params)
    query += " ORDER BY timestamp DESC LIMIT :lim OFFSET :off"
    params["lim"] = limit
    params["off"] = offset
    txs = await database.fetch_all(query, params)
    return {
        "success": True,
        "transactions": [dict(t) for t in txs],
        "page": page,
        "limit": limit,
        "total": total["cnt"],
        "pages": (total["cnt"] + limit - 1) // limit
    }

@app.get("/ledger")
async def get_ledger(
    user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM ledger WHERE user_phone=:p", {"p": user["phone"]})
    entries = await database.fetch_all(
        "SELECT * FROM ledger WHERE user_phone=:p ORDER BY created_at DESC LIMIT :lim OFFSET :off",
        {"p": user["phone"], "lim": limit, "off": offset}
    )
    return {
        "success": True,
        "ledger": [dict(e) for e in entries],
        "page": page, "total": total["cnt"],
        "pages": (total["cnt"] + limit - 1) // limit
    }

# ====== Routes: طلب التاجر ======
@app.post("/seller/request")
@limiter.limit("3/minute")
async def request_seller(request: Request, data: SellerRequestModel, user=Depends(get_current_user)):
    existing = await database.fetch_one(
        "SELECT id FROM seller_requests WHERE phone=:p AND status='pending'", {"p": user["phone"]}
    )
    if existing:
        return {"success": False, "message": "لديك طلب قيد المراجعة بالفعل"}
    if user["is_seller"] and user["seller_approved"]:
        return {"success": False, "message": "أنت تاجر معتمد بالفعل"}

    await database.execute(
        """INSERT INTO seller_requests (phone,shop_name,shop_description,product_types,is_digital,extra_info,status,created_at)
           VALUES(:p,:sn,:sd,:pt,:id,:ei,'pending',:t)""",
        {"p": user["phone"], "sn": data.shop_name, "sd": data.shop_description,
         "pt": data.product_types, "id": int(data.is_digital), "ei": data.extra_info, "t": datetime.utcnow()}
    )
    await database.execute("UPDATE users SET is_seller=1 WHERE phone=:p", {"p": user["phone"]})

    admin_user = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": ADMIN_PHONE})
    await database.execute(
        """INSERT INTO chat_messages (sender_phone,receiver_phone,message,message_type,created_at)
           VALUES(:s,:r,:m,'seller_request',:t)""",
        {
            "s": user["phone"], "r": ADMIN_PHONE,
            "m": f"🏪 طلب تسجيل تاجر جديد\n\nالاسم: {user['name']}\nالهاتف: {user['phone']}\nاسم المتجر: {data.shop_name}\nالوصف: {data.shop_description}\nأنواع المنتجات: {data.product_types}\nرقمي: {'نعم' if data.is_digital else 'لا'}\nمعلومات إضافية: {data.extra_info or 'لا يوجد'}",
            "t": datetime.utcnow()
        }
    )
    if admin_user and admin_user["telegram_chat_id"]:
        await notify_telegram(
            admin_user["telegram_chat_id"],
            f"🏪 طلب تاجر جديد!\n\n{user['name']} ({user['phone']})\nاسم المتجر: {data.shop_name}"
        )
    return {"success": True, "message": "تم إرسال طلبك، سيراجعه الأدمن قريباً ✅"}

@app.get("/seller/status")
async def seller_status(user=Depends(get_current_user)):
    req = await database.fetch_one(
        "SELECT * FROM seller_requests WHERE phone=:p ORDER BY created_at DESC LIMIT 1",
        {"p": user["phone"]}
    )
    if not req:
        return {"has_request": False}
    return {
        "has_request": True,
        "status": req["status"],
        "admin_note": req["admin_note"],
        "shop_name": req["shop_name"]
    }

# ====== Routes: المتجر - التاجر ======
@app.post("/products")
async def create_product(
    name: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    category: str = Form("عام"),
    product_type: str = Form("digital"),
    thumbnail: Optional[UploadFile] = File(None),
    user=Depends(require_seller)
):
    amount = validate_positive_amount(price)
    if product_type not in ("digital", "physical", "service"):
        return {"success": False, "message": "نوع المنتج غير صالح"}

    thumbnail_url = None
    if thumbnail and thumbnail.filename:
        ftype = get_file_type(thumbnail.filename)
        if ftype != "image":
            return {"success": False, "message": "الصورة المصغرة يجب أن تكون ملف صورة"}
        thumbnail_url, _, _, _ = await save_upload_file(thumbnail, "products")

    pid = await database.execute(
        """INSERT INTO products (name,description,price,seller_phone,category,product_type,thumbnail_url,is_active,total_sales,created_at)
           VALUES(:n,:d,:p,:s,:c,:pt,:t,1,0,:ts)""",
        {"n": name[:200], "d": description[:5000], "p": float(amount), "s": user["phone"],
         "c": category[:100], "pt": product_type, "t": thumbnail_url, "ts": datetime.utcnow()}
    )
    logger.info("منتج جديد id=%s seller=%s", pid, user["phone"])
    return {"success": True, "product_id": pid, "message": "تم إنشاء المنتج ✅"}

@app.post("/products/{product_id}/files")
async def upload_product_files(
    product_id: int,
    files: List[UploadFile] = File(...),
    is_preview: int = Form(0),
    user=Depends(require_seller)
):
    product = await database.fetch_one("SELECT * FROM products WHERE id=:i", {"i": product_id})
    if not product:
        return {"success": False, "message": "المنتج غير موجود"}
    if product["seller_phone"] != user["phone"]:
        return {"success": False, "message": "ليس منتجك"}

    current_count = await database.fetch_one(
        "SELECT COUNT(*) as cnt FROM product_files WHERE product_id=:i", {"i": product_id}
    )
    if current_count["cnt"] + len(files) > MAX_PRODUCT_FILES:
        return {"success": False, "message": f"الحد الأقصى {MAX_PRODUCT_FILES} ملفات للمنتج"}

    uploaded = []
    for file in files:
        if not file.filename:
            continue
        try:
            url, fname, ftype, fsize = await save_upload_file(file, "products")
            fid = await database.execute(
                """INSERT INTO product_files (product_id,file_url,file_name,file_type,file_size,is_preview,created_at)
                   VALUES(:pi,:fu,:fn,:ft,:fs,:ip,:t)""",
                {"pi": product_id, "fu": url, "fn": fname, "ft": ftype, "fs": fsize, "ip": is_preview, "t": datetime.utcnow()}
            )
            uploaded.append({"id": fid, "name": fname, "type": ftype, "url": url if is_preview else "مخفي حتى الشراء"})
        except HTTPException as e:
            uploaded.append({"name": file.filename, "error": e.detail})
        except Exception as e:
            logger.error("upload_product_files خطأ: %s", e)
            uploaded.append({"name": file.filename, "error": "فشل في رفع الملف"})

    return {"success": True, "uploaded": uploaded}

@app.delete("/products/{product_id}/files/{file_id}")
async def delete_product_file(product_id: int, file_id: int, user=Depends(require_seller)):
    product = await database.fetch_one("SELECT seller_phone FROM products WHERE id=:i", {"i": product_id})
    if not product or product["seller_phone"] != user["phone"]:
        return {"success": False, "message": "غير مصرح"}
    pf = await database.fetch_one(
        "SELECT file_url FROM product_files WHERE id=:i AND product_id=:pi", {"i": file_id, "pi": product_id}
    )
    if pf:
        try:
            real_path = pf["file_url"].lstrip("/")
            safe_base = str(Path(UPLOAD_DIR).resolve())
            if str(Path(real_path).resolve()).startswith(safe_base):
                os.remove(real_path)
        except Exception:
            pass
        await database.execute("DELETE FROM product_files WHERE id=:i", {"i": file_id})
    return {"success": True}

@app.put("/products/{product_id}")
async def update_product(
    product_id: int,
    name: str = Form(None),
    description: str = Form(None),
    price: float = Form(None),
    category: str = Form(None),
    is_active: int = Form(None),
    user=Depends(require_seller)
):
    product = await database.fetch_one("SELECT * FROM products WHERE id=:i", {"i": product_id})
    if not product:
        return {"success": False, "message": "غير موجود"}
    if product["seller_phone"] != user["phone"]:
        return {"success": False, "message": "ليس منتجك"}

    updates = {}
    if name is not None:
        updates["name"] = name[:200]
    if description is not None:
        updates["description"] = description[:5000]
    if price is not None:
        updates["price"] = float(validate_positive_amount(price))
    if category is not None:
        updates["category"] = category[:100]
    if is_active is not None:
        updates["is_active"] = 1 if is_active else 0

    if updates:
        set_clause = ", ".join(f"{k}=:{k}" for k in updates)
        updates["id"] = product_id
        await database.execute(f"UPDATE products SET {set_clause} WHERE id=:id", updates)
    return {"success": True}

@app.get("/seller/my-products")
async def my_products(
    user=Depends(require_seller),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM products WHERE seller_phone=:p", {"p": user["phone"]})
    prods = await database.fetch_all(
        "SELECT * FROM products WHERE seller_phone=:p ORDER BY created_at DESC LIMIT :lim OFFSET :off",
        {"p": user["phone"], "lim": limit, "off": offset}
    )
    result = []
    for p in prods:
        files = await database.fetch_all(
            "SELECT id,file_name,file_type,file_size,is_preview FROM product_files WHERE product_id=:i", {"i": p["id"]}
        )
        result.append({**dict(p), "files": [dict(f) for f in files]})
    return {"products": result, "page": page, "total": total["cnt"], "pages": (total["cnt"] + limit - 1) // limit}

@app.get("/seller/my-orders")
async def seller_orders(
    user=Depends(require_seller),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM orders WHERE seller_phone=:p", {"p": user["phone"]})
    orders_list = await database.fetch_all(
        """SELECT o.*,p.name as product_name FROM orders o JOIN products p ON o.product_id=p.id
           WHERE o.seller_phone=:p ORDER BY o.created_at DESC LIMIT :lim OFFSET :off""",
        {"p": user["phone"], "lim": limit, "off": offset}
    )
    return {"orders": [dict(o) for o in orders_list], "page": page, "total": total["cnt"]}

@app.get("/seller/stats")
async def seller_stats(user=Depends(require_seller)):
    total = await database.fetch_one(
        "SELECT COUNT(*) as orders, COALESCE(SUM(seller_amount),0) as revenue FROM orders WHERE seller_phone=:p",
        {"p": user["phone"]}
    )
    products_count = await database.fetch_one(
        "SELECT COUNT(*) as cnt FROM products WHERE seller_phone=:p AND is_active=1", {"p": user["phone"]}
    )
    return {
        "total_orders": total["orders"],
        "total_revenue": float(total["revenue"]),
        "active_products": products_count["cnt"]
    }

# ====== Routes: المتجر - المشتري ======
@app.get("/products")
async def list_products(
    category: Optional[str] = None,
    product_type: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = Query(None, regex="^(price_asc|price_desc|rating|newest|popular)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    user=Depends(get_current_user)
):
    offset = (page - 1) * limit
    conditions = ["p.is_active=1"]
    params = {}

    if category:
        conditions.append("p.category=:cat")
        params["cat"] = category
    if product_type:
        conditions.append("p.product_type=:pt")
        params["pt"] = product_type
    if min_price is not None:
        conditions.append("p.price>=:mn")
        params["mn"] = min_price
    if max_price is not None:
        conditions.append("p.price<=:mx")
        params["mx"] = max_price
    if search:
        # SQL Injection safe - parameterized
        conditions.append("(LOWER(p.name) LIKE :srch OR LOWER(p.description) LIKE :srch OR LOWER(p.category) LIKE :srch)")
        params["srch"] = f"%{search.lower()[:100]}%"

    where = " AND ".join(conditions)

    sort_map = {
        "price_asc": "p.price ASC",
        "price_desc": "p.price DESC",
        "rating": "p.rating_avg DESC, p.rating_count DESC",
        "newest": "p.created_at DESC",
        "popular": "p.total_sales DESC, p.created_at DESC",
    }
    order = sort_map.get(sort_by or "", "p.total_sales DESC, p.created_at DESC")

    count_q = f"SELECT COUNT(*) as cnt FROM products p WHERE {where}"
    total = await database.fetch_one(count_q, params)

    params["lim"] = limit
    params["off"] = offset
    query = f"""SELECT p.*,u.shop_name,u.name as seller_name FROM products p
                JOIN users u ON p.seller_phone=u.phone WHERE {where}
                ORDER BY {order} LIMIT :lim OFFSET :off"""
    prods = await database.fetch_all(query, params)

    result = []
    for p in prods:
        previews = await database.fetch_all(
            "SELECT file_url,file_name,file_type FROM product_files WHERE product_id=:i AND is_preview=1", {"i": p["id"]}
        )
        result.append({**dict(p), "preview_files": [dict(f) for f in previews]})

    return {
        "products": result,
        "page": page,
        "total": total["cnt"],
        "pages": (total["cnt"] + limit - 1) // limit
    }

@app.get("/products/{product_id}")
async def get_product(product_id: int, user=Depends(get_current_user)):
    p = await database.fetch_one(
        """SELECT p.*,u.shop_name,u.name as seller_name,u.avatar_url as seller_avatar
           FROM products p JOIN users u ON p.seller_phone=u.phone WHERE p.id=:i AND p.is_active=1""",
        {"i": product_id}
    )
    if not p:
        return {"success": False, "message": "المنتج غير موجود"}

    previews = await database.fetch_all(
        "SELECT file_url,file_name,file_type FROM product_files WHERE product_id=:i AND is_preview=1", {"i": product_id}
    )
    reviews_list = await database.fetch_all(
        """SELECT r.rating,r.comment,r.created_at,u.name as buyer_name FROM reviews r
           JOIN users u ON r.buyer_phone=u.phone WHERE r.product_id=:i ORDER BY r.created_at DESC LIMIT 20""",
        {"i": product_id}
    )
    purchased = await database.fetch_one(
        "SELECT id,download_token FROM orders WHERE buyer_phone=:p AND product_id=:i",
        {"p": user["phone"], "i": product_id}
    )

    result = {**dict(p), "preview_files": [dict(f) for f in previews],
              "reviews": [dict(r) for r in reviews_list], "purchased": bool(purchased)}
    if purchased:
        result["download_token"] = purchased["download_token"]
    return {"success": True, "product": result}

@app.post("/buy-product")
@limiter.limit("10/minute")
async def buy_product(request: Request, data: BuyProduct, user=Depends(get_current_user)):
    product = await database.fetch_one("SELECT * FROM products WHERE id=:i AND is_active=1", {"i": data.product_id})
    if not product:
        return {"success": False, "message": "المنتج غير موجود أو غير متاح"}
    if product["seller_phone"] == user["phone"]:
        return {"success": False, "message": "لا يمكن شراء منتجك الخاص"}

    already = await database.fetch_one(
        "SELECT id FROM orders WHERE buyer_phone=:p AND product_id=:i",
        {"p": user["phone"], "i": data.product_id}
    )
    if already:
        return {"success": False, "message": "اشتريت هذا المنتج من قبل"}

    amount = to_decimal(product["price"])
    fee = calc_platform_fee(amount)
    seller_amount = (amount - fee).quantize(Decimal("0.000001"), rounding=ROUND_DOWN)

    now = datetime.utcnow()
    download_token = generate_download_token()
    ref_id = uuid.uuid4().hex

    async with database.transaction():
        # خصم ذري - منع Race Condition
        result = await database.execute(
            "UPDATE users SET balance=balance-:a WHERE phone=:p AND balance>=:a",
            {"a": float(amount), "p": user["phone"]}
        )
        if result == 0:
            raise HTTPException(400, "الرصيد غير كافٍ")

        await database.execute(
            "UPDATE users SET balance=balance+:a WHERE phone=:p",
            {"a": float(seller_amount), "p": product["seller_phone"]}
        )
        await add_platform_earning(fee, f"عمولة منتج #{data.product_id}")

        order_id = await database.execute(
            """INSERT INTO orders (buyer_phone,seller_phone,product_id,amount,platform_fee,seller_amount,status,download_token,created_at)
               VALUES(:b,:s,:pid,:a,:f,:sa,'completed',:dt,:t)""",
            {"b": user["phone"], "s": product["seller_phone"], "pid": data.product_id,
             "a": float(amount), "f": float(fee), "sa": float(seller_amount), "dt": download_token, "t": now}
        )
        await database.execute("UPDATE products SET total_sales=total_sales+1 WHERE id=:i", {"i": data.product_id})

        await database.execute(
            """INSERT INTO transactions (user_phone,type,amount,fee,status,related_phone,description,ref_id,timestamp)
               VALUES(:p,'product_purchase',:a,:f,'completed',:r,:d,:ref,:t)""",
            {"p": user["phone"], "a": float(amount), "f": float(fee),
             "r": product["seller_phone"], "d": f"شراء: {product['name']}", "ref": ref_id, "t": now}
        )
        await database.execute(
            """INSERT INTO transactions (user_phone,type,amount,fee,status,related_phone,description,ref_id,timestamp)
               VALUES(:p,'product_sale',:a,0,'completed',:r,:d,:ref,:t)""",
            {"p": product["seller_phone"], "a": float(seller_amount),
             "r": user["phone"], "d": f"بيع: {product['name']}", "ref": ref_id, "t": now}
        )

        # Ledger entries
        buyer_row = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": user["phone"]})
        seller_row = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": product["seller_phone"]})
        buyer_bal = to_decimal(buyer_row["balance"])
        seller_bal = to_decimal(seller_row["balance"])

        await write_ledger(user["phone"], "debit", amount,
                           buyer_bal + amount, buyer_bal, "purchase", str(order_id), f"شراء: {product['name']}")
        await write_ledger(product["seller_phone"], "credit", seller_amount,
                           seller_bal - seller_amount, seller_bal, "sale", str(order_id), f"بيع: {product['name']}")

    seller = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": product["seller_phone"]})
    if seller:
        await notify_telegram(
            seller["telegram_chat_id"],
            f"🛒 بيع جديد!\n\nالمنتج: {product['name']}\nالمبلغ: *{seller_amount} USDT*\nالمشتري: {user['name']}"
        )

    return {
        "success": True,
        "message": "تم الشراء بنجاح ✅",
        "order_id": order_id,
        "download_token": download_token,
        "paid": float(amount),
        "fee": float(fee)
    }

@app.get("/download/{download_token}/{file_id}")
async def download_single_file(download_token: str, file_id: int, user=Depends(get_current_user)):
    # التحقق من الـ token - منع Path Traversal
    if not re.match(r'^[a-f0-9]{64}$', download_token):
        raise HTTPException(400, "رمز تحميل غير صالح")

    order = await database.fetch_one(
        "SELECT * FROM orders WHERE download_token=:t AND buyer_phone=:p",
        {"t": download_token, "p": user["phone"]}
    )
    if not order:
        raise HTTPException(403, "غير مصرح - يجب شراء المنتج أولاً")

    pf = await database.fetch_one(
        "SELECT * FROM product_files WHERE id=:fi AND product_id=:pi AND is_preview=0",
        {"fi": file_id, "pi": order["product_id"]}
    )
    if not pf:
        raise HTTPException(404, "الملف غير موجود")

    real_path = pf["file_url"].lstrip("/")
    # Path Traversal Protection
    safe_base = str(Path(UPLOAD_DIR).resolve())
    resolved = str(Path(real_path).resolve())
    if not resolved.startswith(safe_base):
        raise HTTPException(403, "مسار غير مصرح")

    if not os.path.exists(real_path):
        raise HTTPException(404, "الملف غير موجود على السيرفر")

    return FileResponse(path=real_path, filename=pf["file_name"], media_type="application/octet-stream")

@app.get("/download/{download_token}")
async def list_download_files(download_token: str, user=Depends(get_current_user)):
    if not re.match(r'^[a-f0-9]{64}$', download_token):
        return {"success": False, "message": "رمز تحميل غير صالح"}

    order = await database.fetch_one(
        "SELECT * FROM orders WHERE download_token=:t AND buyer_phone=:p",
        {"t": download_token, "p": user["phone"]}
    )
    if not order:
        return {"success": False, "message": "رمز التحميل غير صالح"}

    files = await database.fetch_all(
        "SELECT id,file_name,file_type,file_size FROM product_files WHERE product_id=:i AND is_preview=0",
        {"i": order["product_id"]}
    )
    safe_files = [
        {
            "id": f["id"],
            "name": f["file_name"],
            "type": f["file_type"],
            "size_mb": round(f["file_size"] / (1024 * 1024), 2),
            "download_url": f"/download/{download_token}/{f['id']}"
        }
        for f in files
    ]
    return {"success": True, "files": safe_files}

@app.post("/reviews")
async def add_review(data: ReviewModel, user=Depends(get_current_user)):
    order = await database.fetch_one(
        "SELECT id FROM orders WHERE id=:oi AND buyer_phone=:p AND product_id=:pi",
        {"oi": data.order_id, "p": user["phone"], "pi": data.product_id}
    )
    if not order:
        return {"success": False, "message": "يجب شراء المنتج أولاً"}

    existing = await database.fetch_one("SELECT id FROM reviews WHERE order_id=:oi", {"oi": data.order_id})
    if existing:
        return {"success": False, "message": "قيّمت هذا المنتج من قبل"}

    await database.execute(
        "INSERT INTO reviews (order_id,product_id,buyer_phone,rating,comment,created_at) VALUES(:oi,:pi,:p,:r,:c,:t)",
        {"oi": data.order_id, "pi": data.product_id, "p": user["phone"],
         "r": data.rating, "c": data.comment, "t": datetime.utcnow()}
    )
    avg = await database.fetch_one(
        "SELECT AVG(CAST(rating AS FLOAT)) as avg, COUNT(*) as cnt FROM reviews WHERE product_id=:i",
        {"i": data.product_id}
    )
    await database.execute(
        "UPDATE products SET rating_avg=:a, rating_count=:c WHERE id=:i",
        {"a": round(avg["avg"], 1), "c": avg["cnt"], "i": data.product_id}
    )
    return {"success": True, "message": "تم إضافة تقييمك ✅"}

@app.get("/products/{product_id}/reviews")
async def get_product_reviews(
    product_id: int,
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    user=Depends(get_current_user)
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM reviews WHERE product_id=:i", {"i": product_id})
    reviews_list = await database.fetch_all(
        """SELECT r.rating,r.comment,r.created_at,u.name as buyer_name
           FROM reviews r JOIN users u ON r.buyer_phone=u.phone
           WHERE r.product_id=:i ORDER BY r.created_at DESC LIMIT :lim OFFSET :off""",
        {"i": product_id, "lim": limit, "off": offset}
    )
    return {"reviews": [dict(r) for r in reviews_list], "page": page, "total": total["cnt"]}

@app.get("/my-purchases")
async def my_purchases(
    user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM orders WHERE buyer_phone=:p", {"p": user["phone"]})
    orders_list = await database.fetch_all(
        """SELECT o.*,p.name as product_name,p.thumbnail_url,p.seller_phone,u.shop_name
           FROM orders o JOIN products p ON o.product_id=p.id JOIN users u ON o.seller_phone=u.phone
           WHERE o.buyer_phone=:p ORDER BY o.created_at DESC LIMIT :lim OFFSET :off""",
        {"p": user["phone"], "lim": limit, "off": offset}
    )
    return {"purchases": [dict(o) for o in orders_list], "page": page, "total": total["cnt"]}

# ====== Routes: الدردشة ======
@app.post("/chat/send")
@limiter.limit("30/minute")
async def send_message(request: Request, data: SendMessage, user=Depends(get_current_user)):
    receiver = data.receiver_phone or ADMIN_PHONE
    if not user["is_admin"] and receiver != ADMIN_PHONE:
        return {"success": False, "message": "يمكنك التحدث مع الأدمن فقط"}

    await database.execute(
        "INSERT INTO chat_messages (sender_phone,receiver_phone,message,message_type,created_at) VALUES(:s,:r,:m,'text',:t)",
        {"s": user["phone"], "r": receiver, "m": data.message, "t": datetime.utcnow()}
    )
    recv_user = await database.fetch_one("SELECT telegram_chat_id,name FROM users WHERE phone=:p", {"p": receiver})
    if recv_user and recv_user["telegram_chat_id"]:
        await notify_telegram(recv_user["telegram_chat_id"], f"💬 رسالة جديدة من {user['name']}\n\n{data.message}")
    return {"success": True}

@app.get("/chat/messages")
async def get_messages(
    user=Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=50),
):
    if user["is_admin"]:
        offset = (page - 1) * limit
        conversations = await database.fetch_all(
            """SELECT DISTINCT sender_phone,
               (SELECT name FROM users WHERE phone=sender_phone) as sender_name,
               (SELECT COUNT(*) FROM chat_messages WHERE sender_phone=m.sender_phone AND receiver_phone=:admin AND is_read=0) as unread,
               (SELECT MAX(created_at) FROM chat_messages WHERE sender_phone=m.sender_phone AND receiver_phone=:admin) as last_msg_at
               FROM chat_messages m WHERE receiver_phone=:admin
               ORDER BY last_msg_at DESC LIMIT :lim OFFSET :off""",
            {"admin": ADMIN_PHONE, "lim": limit, "off": offset}
        )
        return {"is_admin": True, "conversations": [dict(c) for c in conversations]}
    else:
        offset = (page - 1) * limit
        total = await database.fetch_one(
            """SELECT COUNT(*) as cnt FROM chat_messages WHERE
               (sender_phone=:p AND receiver_phone=:a) OR (sender_phone=:a AND receiver_phone=:p)""",
            {"p": user["phone"], "a": ADMIN_PHONE}
        )
        msgs = await database.fetch_all(
            """SELECT id,sender_phone,message,message_type,is_read,created_at FROM chat_messages WHERE
               (sender_phone=:p AND receiver_phone=:a) OR (sender_phone=:a AND receiver_phone=:p)
               ORDER BY created_at ASC LIMIT :lim OFFSET :off""",
            {"p": user["phone"], "a": ADMIN_PHONE, "lim": limit, "off": offset}
        )
        await database.execute(
            "UPDATE chat_messages SET is_read=1 WHERE receiver_phone=:p AND sender_phone=:a AND is_read=0",
            {"p": user["phone"], "a": ADMIN_PHONE}
        )
        return {"messages": [dict(m) for m in msgs], "page": page, "total": total["cnt"]}

@app.get("/chat/conversation/{phone}")
async def get_conversation(
    phone: str,
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=50),
    admin=Depends(require_admin)
):
    offset = (page - 1) * limit
    total = await database.fetch_one(
        """SELECT COUNT(*) as cnt FROM chat_messages WHERE
           (sender_phone=:p AND receiver_phone=:a) OR (sender_phone=:a AND receiver_phone=:p)""",
        {"p": phone, "a": ADMIN_PHONE}
    )
    msgs = await database.fetch_all(
        """SELECT * FROM chat_messages WHERE
           (sender_phone=:p AND receiver_phone=:a) OR (sender_phone=:a AND receiver_phone=:p)
           ORDER BY created_at ASC LIMIT :lim OFFSET :off""",
        {"p": phone, "a": ADMIN_PHONE, "lim": limit, "off": offset}
    )
    await database.execute(
        "UPDATE chat_messages SET is_read=1 WHERE receiver_phone=:a AND sender_phone=:p AND is_read=0",
        {"a": ADMIN_PHONE, "p": phone}
    )
    user_info = await database.fetch_one(
        "SELECT name,phone,is_seller,seller_approved,balance FROM users WHERE phone=:p", {"p": phone}
    )
    return {"messages": [dict(m) for m in msgs], "user": dict(user_info) if user_info else None,
            "page": page, "total": total["cnt"]}

@app.post("/chat/reply")
async def admin_reply(data: AdminReplyModel, admin=Depends(require_admin)):
    await database.execute(
        "INSERT INTO chat_messages (sender_phone,receiver_phone,message,message_type,created_at) VALUES(:s,:r,:m,'text',:t)",
        {"s": ADMIN_PHONE, "r": data.receiver_phone, "m": data.message[:2000], "t": datetime.utcnow()}
    )
    recv_user = await database.fetch_one("SELECT telegram_chat_id FROM users WHERE phone=:p", {"p": data.receiver_phone})
    if recv_user and recv_user["telegram_chat_id"]:
        await notify_telegram(recv_user["telegram_chat_id"], f"💬 رد من الإدارة:\n\n{data.message}")
    return {"success": True}

# ====== Routes: Admin ======
@app.get("/admin/seller-requests")
async def admin_seller_requests(
    admin=Depends(require_admin),
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    conditions = []
    params = {"lim": limit, "off": offset}
    if status:
        conditions.append("sr.status=:st")
        params["st"] = status
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    total = await database.fetch_one(f"SELECT COUNT(*) as cnt FROM seller_requests sr {where}", params)
    reqs = await database.fetch_all(
        f"""SELECT sr.*,u.name as user_name,u.balance FROM seller_requests sr
            JOIN users u ON sr.phone=u.phone {where}
            ORDER BY sr.created_at DESC LIMIT :lim OFFSET :off""",
        params
    )
    return {"requests": [dict(r) for r in reqs], "page": page, "total": total["cnt"]}

@app.post("/admin/approve-seller")
async def approve_seller(data: ApproveSellerModel, admin=Depends(require_admin), request: Request = None):
    user = await database.fetch_one("SELECT * FROM users WHERE phone=:p", {"p": data.phone})
    if not user:
        return {"success": False, "message": "المستخدم غير موجود"}

    if data.approved:
        req = await database.fetch_one(
            "SELECT shop_name,shop_description FROM seller_requests WHERE phone=:p ORDER BY created_at DESC LIMIT 1",
            {"p": data.phone}
        )
        await database.execute(
            "UPDATE users SET is_seller=1, seller_approved=1, shop_name=:sn, shop_description=:sd WHERE phone=:p",
            {"sn": req["shop_name"] if req else "", "sd": req["shop_description"] if req else "", "p": data.phone}
        )
        await database.execute(
            "UPDATE seller_requests SET status='approved', admin_note=:n, reviewed_at=:t WHERE phone=:p AND status='pending'",
            {"n": data.admin_note, "t": datetime.utcnow(), "p": data.phone}
        )
        msg = f"🎉 تهانينا! تم قبول طلبك كتاجر في المنصة.\n{'ملاحظة: ' + data.admin_note if data.admin_note else ''}"
    else:
        await database.execute("UPDATE users SET is_seller=0, seller_approved=0 WHERE phone=:p", {"p": data.phone})
        await database.execute(
            "UPDATE seller_requests SET status='rejected', admin_note=:n, reviewed_at=:t WHERE phone=:p AND status='pending'",
            {"n": data.admin_note, "t": datetime.utcnow(), "p": data.phone}
        )
        msg = f"❌ تم رفض طلبك كتاجر.\n{'السبب: ' + data.admin_note if data.admin_note else ''}"

    await database.execute(
        "INSERT INTO chat_messages (sender_phone,receiver_phone,message,message_type,created_at) VALUES(:s,:r,:m,'system',:t)",
        {"s": ADMIN_PHONE, "r": data.phone, "m": msg, "t": datetime.utcnow()}
    )
    await notify_telegram(user["telegram_chat_id"], msg)
    await audit(admin["phone"], "approve_seller" if data.approved else "reject_seller",
                target_phone=data.phone, details=data.admin_note, request=request)
    return {"success": True, "approved": data.approved}

@app.get("/admin/platform-profit")
async def platform_profit(admin=Depends(require_admin)):
    total = await database.fetch_one("SELECT COALESCE(SUM(amount),0) as total, COUNT(*) as count FROM platform_account")
    withdraws = await database.fetch_one("SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE type='withdraw'")
    deposits = await database.fetch_one("SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE type='deposit'")
    sales = await database.fetch_one("SELECT COUNT(*) as count, COALESCE(SUM(platform_fee),0) as fees FROM orders")
    users_count = await database.fetch_one("SELECT COUNT(*) as total, COALESCE(SUM(balance),0) as balance_total FROM users")
    sellers_count = await database.fetch_one("SELECT COUNT(*) as cnt FROM users WHERE is_seller=1 AND seller_approved=1")
    pending_requests = await database.fetch_one("SELECT COUNT(*) as cnt FROM seller_requests WHERE status='pending'")
    pending_withdrawals = await database.fetch_one("SELECT COUNT(*) as cnt FROM withdrawals WHERE status='pending'")

    return {
        "total_earnings": float(total["total"]),
        "total_withdrawals": float(withdraws["total"]),
        "total_deposits": float(deposits["total"]),
        "total_orders": sales["count"],
        "orders_fees": float(sales["fees"]),
        "total_users": users_count["total"],
        "total_balance": float(users_count["balance_total"]),
        "total_sellers": sellers_count["cnt"],
        "pending_seller_requests": pending_requests["cnt"],
        "pending_withdrawals": pending_withdrawals["cnt"],
        "settings": {
            "transfer_fee": f"{TRANSFER_FEE_PERCENT}%",
            "withdraw_fee": f"{WITHDRAW_FEE_FIXED} USDT",
            "product_fee": f"{PLATFORM_FEE_PERCENT}%",
            "min_withdraw": MIN_WITHDRAW,
            "max_daily": MAX_DAILY_WITHDRAW
        }
    }

@app.get("/admin/users")
async def admin_users(
    admin=Depends(require_admin),
    search: Optional[str] = None,
    is_banned: Optional[int] = None,
    is_seller: Optional[int] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    conditions = []
    params = {"lim": limit, "off": offset}
    if search:
        conditions.append("(phone LIKE :s OR name LIKE :s OR email LIKE :s)")
        params["s"] = f"%{search[:50]}%"
    if is_banned is not None:
        conditions.append("is_banned=:ib")
        params["ib"] = is_banned
    if is_seller is not None:
        conditions.append("is_seller=:isl")
        params["isl"] = is_seller
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    total = await database.fetch_one(f"SELECT COUNT(*) as cnt FROM users {where}", params)
    all_users = await database.fetch_all(
        f"""SELECT phone,name,email,balance,is_banned,is_seller,seller_approved,shop_name,
               telegram_chat_id,referral_code,created_at
           FROM users {where} ORDER BY balance DESC LIMIT :lim OFFSET :off""",
        params
    )
    return {"users": [dict(u) for u in all_users], "page": page, "total": total["cnt"]}

@app.get("/admin/products")
async def admin_products(
    admin=Depends(require_admin),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM products")
    prods = await database.fetch_all(
        """SELECT p.*,u.name as seller_name FROM products p JOIN users u ON p.seller_phone=u.phone
           ORDER BY p.created_at DESC LIMIT :lim OFFSET :off""",
        {"lim": limit, "off": offset}
    )
    return {"products": [dict(p) for p in prods], "page": page, "total": total["cnt"]}

@app.post("/admin/toggle-product/{product_id}")
async def admin_toggle_product(product_id: int, admin=Depends(require_admin), request: Request = None):
    product = await database.fetch_one("SELECT id,name,is_active FROM products WHERE id=:i", {"i": product_id})
    if not product:
        return {"success": False, "message": "المنتج غير موجود"}
    await database.execute(
        "UPDATE products SET is_active=CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=:i", {"i": product_id}
    )
    await audit(admin["phone"], "toggle_product", target_id=str(product_id),
                details=f"المنتج: {product['name']}", request=request)
    return {"success": True}

@app.get("/admin/orders")
async def admin_orders(
    admin=Depends(require_admin),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    total = await database.fetch_one("SELECT COUNT(*) as cnt FROM orders")
    all_orders = await database.fetch_all(
        """SELECT o.*,p.name as product_name,u1.name as buyer_name,u2.name as seller_name
           FROM orders o JOIN products p ON o.product_id=p.id
           JOIN users u1 ON o.buyer_phone=u1.phone JOIN users u2 ON o.seller_phone=u2.phone
           ORDER BY o.created_at DESC LIMIT :lim OFFSET :off""",
        {"lim": limit, "off": offset}
    )
    return {"orders": [dict(o) for o in all_orders], "page": page, "total": total["cnt"]}

@app.post("/admin/ban/{phone}")
async def ban(phone: str, admin=Depends(require_admin), request: Request = None):
    if phone == ADMIN_PHONE:
        return {"success": False, "message": "لا يمكن حظر الأدمن"}
    user = await database.fetch_one("SELECT name FROM users WHERE phone=:p", {"p": phone})
    if not user:
        return {"success": False, "message": "المستخدم غير موجود"}
    async with database.transaction():
        await database.execute("UPDATE users SET is_banned=1 WHERE phone=:p", {"p": phone})
        # إبطال جميع جلسات المستخدم المحظور
        await revoke_all_tokens_for_user(phone)
    await audit(admin["phone"], "ban", target_phone=phone, request=request)
    logger.info("حظر مستخدم: %s by %s", phone, admin["phone"])
    return {"success": True}

@app.post("/admin/unban/{phone}")
async def unban(phone: str, admin=Depends(require_admin), request: Request = None):
    await database.execute("UPDATE users SET is_banned=0 WHERE phone=:p", {"p": phone})
    await audit(admin["phone"], "unban", target_phone=phone, request=request)
    return {"success": True}

@app.post("/admin/adjust-balance")
async def adjust(data: AdjustBalance, admin=Depends(require_admin), request: Request = None):
    user = await database.fetch_one("SELECT name,balance FROM users WHERE phone=:p", {"p": data.phone})
    if not user:
        return {"success": False, "message": "المستخدم غير موجود"}

    amount = to_decimal(data.amount)
    ref_id = uuid.uuid4().hex

    async with database.transaction():
        await database.execute(
            "UPDATE users SET balance=balance+:a WHERE phone=:p", {"a": float(amount), "p": data.phone}
        )
        await database.execute(
            """INSERT INTO transactions (user_phone,type,amount,fee,status,description,ref_id,timestamp)
               VALUES(:p,'admin_adjust',:a,0,'completed',:d,:ref,:t)""",
            {"p": data.phone, "a": float(amount), "d": f"تعديل إداري: {data.note}", "ref": ref_id, "t": datetime.utcnow()}
        )
        user_row = await database.fetch_one("SELECT balance FROM users WHERE phone=:p", {"p": data.phone})
        new_balance = to_decimal(user_row["balance"])
        old_balance = new_balance - amount
        await write_ledger(
            data.phone, "credit" if amount >= 0 else "debit",
            abs(amount), old_balance, new_balance,
            "admin_adjust", ref_id, f"تعديل إداري: {data.note}"
        )

    await audit(admin["phone"], "adjust_balance", target_phone=data.phone,
                details=f"المبلغ: {amount} - {data.note}", request=request)
    return {"success": True}

@app.get("/admin/audit-logs")
async def get_audit_logs(
    admin=Depends(require_admin),
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    action: Optional[str] = None,
    target_phone: Optional[str] = None,
):
    offset = (page - 1) * limit
    conditions = []
    params = {"lim": limit, "off": offset}
    if action:
        conditions.append("action=:ac")
        params["ac"] = action
    if target_phone:
        conditions.append("target_phone=:tp")
        params["tp"] = target_phone
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    total = await database.fetch_one(f"SELECT COUNT(*) as cnt FROM audit_logs {where}", params)
    logs = await database.fetch_all(
        f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT :lim OFFSET :off", params
    )
    return {"logs": [dict(l) for l in logs], "page": page, "total": total["cnt"]}

@app.get("/admin/withdrawals")
async def admin_withdrawals(
    admin=Depends(require_admin),
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
):
    offset = (page - 1) * limit
    conditions = []
    params = {"lim": limit, "off": offset}
    if status:
        conditions.append("w.status=:st")
        params["st"] = status
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    total = await database.fetch_one(f"SELECT COUNT(*) as cnt FROM withdrawals w {where}", params)
    wds = await database.fetch_all(
        f"""SELECT w.*,u.name as user_name FROM withdrawals w JOIN users u ON w.user_phone=u.phone
            {where} ORDER BY w.created_at DESC LIMIT :lim OFFSET :off""",
        params
    )
    return {"withdrawals": [dict(w) for w in wds], "page": page, "total": total["cnt"]}

@app.get("/admin/panel", response_class=HTMLResponse)
async def admin_panel(admin=Depends(require_admin)):
    s = await database.fetch_one("SELECT COUNT(*) as u, COALESCE(SUM(balance),0) as b FROM users")
    p = await database.fetch_one("SELECT COALESCE(SUM(amount),0) as profit FROM platform_account")
    o = await database.fetch_one("SELECT COUNT(*) as cnt FROM orders")
    d = await database.fetch_one("SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE type='deposit'")
    pending = await database.fetch_one("SELECT COUNT(*) as cnt FROM seller_requests WHERE status='pending'")
    unread_chat = await database.fetch_one("SELECT COUNT(*) as cnt FROM chat_messages WHERE receiver_phone=:p AND is_read=0", {"p": ADMIN_PHONE})
    pending_wd = await database.fetch_one("SELECT COUNT(*) as cnt FROM withdrawals WHERE status='pending'")
    all_users = await database.fetch_all(
        "SELECT phone,name,balance,is_banned,is_seller,seller_approved,telegram_chat_id FROM users ORDER BY balance DESC LIMIT 100"
    )
    seller_reqs = await database.fetch_all(
        """SELECT sr.*,u.name FROM seller_requests sr JOIN users u ON sr.phone=u.phone
           WHERE sr.status='pending' ORDER BY sr.created_at DESC"""
    )

    user_rows = "".join(
        f"<tr><td>{u['phone']}</td><td>{u['name']}</td><td>{float(u['balance']):.2f}</td>"
        f"<td>{'✅ تاجر' if u['is_seller'] and u['seller_approved'] else '👤 عادي'}</td>"
        f"<td>{'✅' if u['telegram_chat_id'] else '❌'}</td>"
        f"<td>{'🔴' if u['is_banned'] else '🟢'}</td></tr>"
        for u in all_users
    )
    req_rows = "".join(
        f"<tr><td>{r['phone']}</td><td>{r['name']}</td><td>{r['shop_name']}</td>"
        f"<td>{r['product_types']}</td><td>{'رقمي' if r['is_digital'] else 'مادي'}</td>"
        f"<td><a href='/admin/approve-quick/{r['phone']}/1' style='color:#00ff88'>قبول</a> | "
        f"<a href='/admin/approve-quick/{r['phone']}/0' style='color:#ff4466'>رفض</a></td></tr>"
        for r in seller_reqs
    )

    return f"""<!DOCTYPE html><html dir="rtl"><head><meta charset="UTF-8"><title>لوحة الإدارة</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Arial;background:#080810;color:#e0e0e0;padding:30px}}
h1{{color:#00ff88;font-size:26px;margin-bottom:4px}}
h2{{color:#555;font-size:15px;margin-bottom:25px}}
h3{{color:#00ff88;margin:25px 0 12px;font-size:16px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px}}
.card{{background:#12121f;padding:22px;border-radius:14px;border:1px solid #00ff8820;text-align:center}}
.card p{{color:#777;font-size:12px;margin-bottom:8px}}
.card h3{{color:#00ff88;font-size:22px;font-weight:bold;margin:0}}
table{{width:100%;border-collapse:collapse;background:#0d0d1a;border-radius:12px;overflow:hidden;margin-bottom:30px}}
th{{background:#12121f;padding:12px;text-align:right;color:#00ff88;font-size:13px}}
td{{padding:10px 12px;border-bottom:1px solid #1a1a2e;font-size:13px}}
tr:hover td{{background:#1a1a2e55}}
a{{color:#00ff88;text-decoration:none}}
</style></head>
<body>
<h1>🏦 لوحة إدارة المحفظة</h1>
<h2>مرحباً بك {admin['name']} 👋</h2>

<div class="cards">
<div class="card"><p>المستخدمون</p><h3>{s['u']}</h3></div>
<div class="card"><p>إجمالي الأرصدة</p><h3>{float(s['b']):.2f} $</h3></div>
<div class="card"><p>أرباح المنصة</p><h3>{float(p['profit']):.2f} $</h3></div>
<div class="card"><p>إجمالي الإيداعات</p><h3>{float(d['total']):.2f} $</h3></div>
<div class="card"><p>طلبات الشراء</p><h3>{o['cnt']}</h3></div>
<div class="card"><p>طلبات تاجر معلقة</p><h3 style="color:{'#ffaa00' if pending['cnt']>0 else '#00ff88'}">{pending['cnt']} {'⚠️' if pending['cnt']>0 else '✅'}</h3></div>
<div class="card"><p>رسائل غير مقروءة</p><h3 style="color:{'#ffaa00' if unread_chat['cnt']>0 else '#00ff88'}">{unread_chat['cnt']} {'💬' if unread_chat['cnt']>0 else '✅'}</h3></div>
<div class="card"><p>سحوبات معلقة</p><h3 style="color:{'#ffaa00' if pending_wd['cnt']>0 else '#00ff88'}">{pending_wd['cnt']} {'⏳' if pending_wd['cnt']>0 else '✅'}</h3></div>
</div>

{'<h3>⏳ طلبات التاجر المعلقة</h3><table><tr><th>الهاتف</th><th>الاسم</th><th>المتجر</th><th>أنواع المنتجات</th><th>النوع</th><th>الإجراء</th></tr>' + req_rows + '</table>' if seller_reqs else '<p style="color:#555;margin-bottom:20px">✅ لا توجد طلبات معلقة</p>'}

<h3>👥 المستخدمون (أحدث 100)</h3>
<table>
<tr><th>الهاتف</th><th>الاسم</th><th>الرصيد</th><th>الدور</th><th>تيليجرام</th><th>الحالة</th></tr>
{user_rows}
</table>
</body></html>"""

@app.get("/admin/approve-quick/{phone}/{decision}")
async def approve_quick(phone: str, decision: int, admin=Depends(require_admin), request: Request = None):
    data = ApproveSellerModel(phone=phone, approved=bool(decision))
    return await approve_seller(data, admin, request)
