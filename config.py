import os
from dotenv import load_dotenv
load_dotenv()

# ====== إعدادات المنصة ======
PLATFORM_FEE_PERCENT = 5
WITHDRAW_FEE_FIXED = 2.5
TRANSFER_FEE_PERCENT = 0.3
MIN_WITHDRAW = 20
MAX_DAILY_WITHDRAW = 500
MIN_CONFIRMATIONS = 10
PLATFORM_BONUS = 0

# ====== تيليجرام OTP ======
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
OTP_EXPIRE_MINUTES = 5
OTP_MAX_ATTEMPTS = 5  # عدد المحاولات الخاطئة قبل القفل

# ====== إعدادات البيئة ======
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///wallet.db")
SECRET_KEY = os.getenv("SECRET_KEY")
ENCRYPT_KEY = os.getenv("ENCRYPT_KEY")
ADMIN_PHONE = os.getenv("ADMIN_PHONE")
TRON_API_KEY = os.getenv("TRON_API_KEY")
HOT_WALLET_ADDRESS = os.getenv("HOT_WALLET_ADDRESS")
HOT_WALLET_KEY = os.getenv("HOT_WALLET_KEY")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24
REFRESH_TOKEN_EXPIRE_DAYS = 30

# ====== رفع الملفات ======
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
MAX_FILE_SIZE_MB = 50
ALLOWED_EXTENSIONS = {
    "image": ["jpg", "jpeg", "png", "gif", "webp"],
    "document": ["pdf", "doc", "docx", "txt", "xlsx", "xls"],
    "video": ["mp4", "avi", "mov"],
    "audio": ["mp3", "wav", "ogg"],
    "archive": ["zip", "rar"],
    "other": []
}

# ====== الشبكات ======
NETWORKS = {
    "TRC20": {
        "name": "TRON", "enabled": True,
        "usdt_contract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "fee": 2.5
    },
    "BEP20": {
        "name": "BNB Smart Chain", "enabled": False,
        "usdt_contract": "0x55d398326f99059fF775485246999027B3197955",
        "fee": 0.5
    },
    "POLYGON": {
        "name": "Polygon", "enabled": False,
        "usdt_contract": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "fee": 0.1
    }
}

REFERRAL_BONUS_PERCENT = 1

# ====== المتجر ======
MAX_PRODUCT_FILES = 5
SELLER_REQUEST_AUTO_APPROVE = False

# ====== Pagination ======
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
