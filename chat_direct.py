"""
chat_direct.py — دردشة مباشرة بين المشتري والتاجر

كيف تضيفه لـ main-2.py:
    from chat_direct import router as chat_router
    app.include_router(chat_router)

المتطلبات: نفس قاعدة البيانات الحالية + جدول جديد direct_chats
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from typing import Optional, List
from datetime import datetime
import sqlalchemy
import databases
import uuid

# ── استيراد من مشروعك الحالي ────────────────────────────────────────────────
from config import DATABASE_URL, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
router = APIRouter(prefix="/chat-direct", tags=["Direct Chat"])

from auth import get_current_user
from db import database
# ══════════════════════════════════════════════════════════════════════════════
# جدول الدردشة المباشرة
# ══════════════════════════════════════════════════════════════════════════════
metadata = sqlalchemy.MetaData()

direct_chats = sqlalchemy.Table("direct_chats", metadata,
    sqlalchemy.Column("id",            sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("room_id",       sqlalchemy.String(100), index=True),        # "{buyer}_{seller}_{product_id}"
    sqlalchemy.Column("product_id",    sqlalchemy.Integer, nullable=True),
    sqlalchemy.Column("buyer_phone",   sqlalchemy.String(20)),
    sqlalchemy.Column("seller_phone",  sqlalchemy.String(20)),
    sqlalchemy.Column("sender_phone",  sqlalchemy.String(20)),
    sqlalchemy.Column("message",       sqlalchemy.Text),
    sqlalchemy.Column("msg_type",      sqlalchemy.String(20), default="text"),     # text / image / file / system
    sqlalchemy.Column("is_read",       sqlalchemy.SmallInteger, default=0),
    sqlalchemy.Column("created_at",    sqlalchemy.DateTime, default=datetime.utcnow),
)

# ── أنشئ الجدول إذا ما كان موجود ─────────────────────────────────────────────
def create_tables(engine):
    metadata.create_all(engine, checkfirst=True)


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════════════════════════
class DirectMessage(BaseModel):
    seller_phone: str
    product_id:   Optional[int] = None
    message:      str

    @field_validator("message")
    @classmethod
    def clean(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("الرسالة لا تكون فارغة")
        return v[:2000]

class SellerReply(BaseModel):
    room_id:  str
    message:  str

    @field_validator("message")
    @classmethod
    def clean(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("الرسالة لا تكون فارغة")
        return v[:2000]


# ══════════════════════════════════════════════════════════════════════════════
# دوال مساعدة
# ══════════════════════════════════════════════════════════════════════════════
def make_room_id(buyer: str, seller: str, product_id: Optional[int]) -> str:
    """معرّف غرفة فريد وقابل للاسترجاع"""
    pid = str(product_id) if product_id else "0"
    return f"{buyer}_{seller}_{pid}"

async def get_room_or_404(room_id: str, user_phone: str) -> dict:
    """يتحقق أن المستخدم طرف في هذه الغرفة"""
    row = await database.fetch_one(
        """SELECT DISTINCT buyer_phone, seller_phone, product_id
           FROM direct_chats WHERE room_id=:r LIMIT 1""",
        {"r": room_id}
    )
    if not row:
        raise HTTPException(404, "المحادثة غير موجودة")
    if user_phone not in (row["buyer_phone"], row["seller_phone"]):
        raise HTTPException(403, "غير مصرح")
    return dict(row)

async def mark_read(room_id: str, reader_phone: str):
    """علّم الرسائل كمقروءة للطرف الآخر"""
    await database.execute(
        """UPDATE direct_chats
           SET is_read=1
           WHERE room_id=:r AND sender_phone!=:p AND is_read=0""",
        {"r": room_id, "p": reader_phone}
    )


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/send")
async def send_message(data: DirectMessage, user=Depends(get_current_user)):
    """
    المشتري يبدأ محادثة مع التاجر (أو يرسل رسالة في محادثة موجودة)
    """
    # تحقق أن التاجر موجود ومعتمد
    seller = await database.fetch_one(
        "SELECT phone, name, telegram_chat_id FROM users WHERE phone=:p AND is_seller=1 AND seller_approved=1",
        {"p": data.seller_phone}
    )
    if not seller:
        raise HTTPException(404, "التاجر غير موجود أو غير معتمد")

    if user["phone"] == data.seller_phone:
        raise HTTPException(400, "لا تقدر ترسل لنفسك")

    room_id = make_room_id(user["phone"], data.seller_phone, data.product_id)

    await database.execute(
        """INSERT INTO direct_chats
           (room_id, product_id, buyer_phone, seller_phone, sender_phone, message, msg_type, is_read, created_at)
           VALUES (:rid, :pid, :bp, :sp, :sender, :msg, 'text', 0, :now)""",
        {
            "rid":    room_id,
            "pid":    data.product_id,
            "bp":     user["phone"],
            "sp":     data.seller_phone,
            "sender": user["phone"],
            "msg":    data.message,
            "now":    datetime.utcnow(),
        }
    )

    # إشعار تيليجرام للتاجر
    if seller["telegram_chat_id"]:
        product_info = ""
        if data.product_id:
            p = await database.fetch_one("SELECT name FROM products WHERE id=:i", {"i": data.product_id})
            if p:
                product_info = f"\nالمنتج: {p['name']}"
        await notify_telegram(
            seller["telegram_chat_id"],
            f"💬 رسالة جديدة من {user['name']}{product_info}\n\n{data.message}\n\n👉 room_id: {room_id}"
        )

    return {"success": True, "room_id": room_id}


@router.post("/reply")
async def seller_reply(data: SellerReply, user=Depends(get_current_user)):
    """
    التاجر يرد على محادثة موجودة
    """
    room = await get_room_or_404(data.room_id, user["phone"])

    # التأكد إن المستخدم هو التاجر في هذه الغرفة
    if user["phone"] != room["seller_phone"]:
        # إذا كان المشتري هو اللي يرد، نستخدم /send بدل /reply
        # لكن نسمح له كذلك هنا
        if user["phone"] != room["buyer_phone"]:
            raise HTTPException(403, "غير مصرح")

    await database.execute(
        """INSERT INTO direct_chats
           (room_id, product_id, buyer_phone, seller_phone, sender_phone, message, msg_type, is_read, created_at)
           VALUES (:rid, :pid, :bp, :sp, :sender, :msg, 'text', 0, :now)""",
        {
            "rid":    data.room_id,
            "pid":    room["product_id"],
            "bp":     room["buyer_phone"],
            "sp":     room["seller_phone"],
            "sender": user["phone"],
            "msg":    data.message,
            "now":    datetime.utcnow(),
        }
    )

    # إشعار للطرف الآخر
    other_phone = room["buyer_phone"] if user["phone"] == room["seller_phone"] else room["seller_phone"]
    other = await database.fetch_one("SELECT telegram_chat_id, name FROM users WHERE phone=:p", {"p": other_phone})
    if other and other["telegram_chat_id"]:
        await notify_telegram(
            other["telegram_chat_id"],
            f"💬 رد من {user['name']}\n\n{data.message}"
        )

    return {"success": True}


@router.get("/messages/{room_id}")
async def get_messages(
    room_id: str,
    page:  int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    user=Depends(get_current_user)
):
    """
    جلب رسائل غرفة معينة + تعليمها كمقروءة
    """
    room = await get_room_or_404(room_id, user["phone"])

    offset = (page - 1) * limit
    total = await database.fetch_one(
        "SELECT COUNT(*) as cnt FROM direct_chats WHERE room_id=:r",
        {"r": room_id}
    )
    msgs = await database.fetch_all(
        """SELECT id, sender_phone, message, msg_type, is_read, created_at
           FROM direct_chats WHERE room_id=:r
           ORDER BY created_at ASC LIMIT :lim OFFSET :off""",
        {"r": room_id, "lim": limit, "off": offset}
    )

    # علّم كمقروءة
    await mark_read(room_id, user["phone"])

    # جلب اسم المنتج إن وُجد
    product_name = None
    if room["product_id"]:
        p = await database.fetch_one("SELECT name FROM products WHERE id=:i", {"i": room["product_id"]})
        product_name = p["name"] if p else None

    return {
        "success":      True,
        "room_id":      room_id,
        "product_id":   room["product_id"],
        "product_name": product_name,
        "buyer_phone":  room["buyer_phone"],
        "seller_phone": room["seller_phone"],
        "messages":     [dict(m) for m in msgs],
        "page":         page,
        "total":        total["cnt"],
        "pages":        (total["cnt"] + limit - 1) // limit,
    }


@router.get("/my-rooms")
async def my_rooms(
    page:  int = Query(1, ge=1),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    user=Depends(get_current_user)
):
    """
    قائمة كل محادثاتي (سواء كنت مشتري أو تاجر)
    مرتبة بآخر رسالة + عدد غير المقروءة
    """
    offset = (page - 1) * limit

    rooms_raw = await database.fetch_all(
        """SELECT
               room_id,
               product_id,
               buyer_phone,
               seller_phone,
               MAX(created_at)  AS last_msg_at,
               SUM(CASE WHEN is_read=0 AND sender_phone!=:p THEN 1 ELSE 0 END) AS unread,
               (SELECT message FROM direct_chats dc2
                WHERE dc2.room_id=dc1.room_id ORDER BY created_at DESC LIMIT 1) AS last_message
           FROM direct_chats dc1
           WHERE buyer_phone=:p OR seller_phone=:p
           GROUP BY room_id, product_id, buyer_phone, seller_phone
           ORDER BY last_msg_at DESC
           LIMIT :lim OFFSET :off""",
        {"p": user["phone"], "lim": limit, "off": offset}
    )

    result = []
    for r in rooms_raw:
        # اسم الطرف الآخر
        other_phone = r["seller_phone"] if user["phone"] == r["buyer_phone"] else r["buyer_phone"]
        other = await database.fetch_one("SELECT name FROM users WHERE phone=:p", {"p": other_phone})
        other_name = other["name"] if other else other_phone

        # اسم المنتج
        product_name = None
        if r["product_id"]:
            p = await database.fetch_one("SELECT name FROM products WHERE id=:i", {"i": r["product_id"]})
            product_name = p["name"] if p else None

        result.append({
            "room_id":      r["room_id"],
            "product_id":   r["product_id"],
            "product_name": product_name,
            "other_phone":  other_phone,
            "other_name":   other_name,
            "last_message": r["last_message"],
            "last_msg_at":  r["last_msg_at"],
            "unread":       r["unread"],
            "i_am":         "buyer" if user["phone"] == r["buyer_phone"] else "seller",
        })

    total_count = await database.fetch_one(
        """SELECT COUNT(DISTINCT room_id) as cnt FROM direct_chats
           WHERE buyer_phone=:p OR seller_phone=:p""",
        {"p": user["phone"]}
    )

    return {
        "success": True,
        "rooms":   result,
        "page":    page,
        "total":   total_count["cnt"],
        "pages":   (total_count["cnt"] + limit - 1) // limit,
    }


@router.get("/unread-count")
async def unread_count(user=Depends(get_current_user)):
    """عدد الرسائل غير المقروءة في كل محادثاتي"""
    row = await database.fetch_one(
        """SELECT COUNT(*) as cnt FROM direct_chats
           WHERE (buyer_phone=:p OR seller_phone=:p)
             AND sender_phone!=:p AND is_read=0""",
        {"p": user["phone"]}
    )
    return {"success": True, "unread": row["cnt"] if row else 0}