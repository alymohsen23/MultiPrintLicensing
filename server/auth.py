from datetime import datetime, timedelta, timezone
import os

from passlib.context import CryptContext
from jose import jwt


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


# ============================================================
# JWT SETTINGS
# ============================================================

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set"
    )

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ============================================================
# PASSWORD FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if not password:
        raise ValueError("Password cannot be empty.")

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:

    if not isinstance(plain_password, str):
        return False

    if not isinstance(hashed_password, str):
        return False

    try:
        return pwd_context.verify(
            plain_password,
            hashed_password
        )
    except Exception:
        return False


# ============================================================
# JWT TOKEN
# ============================================================

def create_access_token(data: dict) -> str:

    payload = data.copy()

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload["exp"] = expire

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )
