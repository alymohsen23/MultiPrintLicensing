from datetime import datetime, timedelta, timezone
import os

from passlib.context import CryptContext
from jose import jwt


# ==================================================
# PASSWORD HASHING
# ==================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


# ==================================================
# JWT SETTINGS
# ==================================================

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ==================================================
# PASSWORD FUNCTIONS
# ==================================================

def hash_password(password: str) -> str:

    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        raise ValueError(
            "Password cannot be longer than 72 UTF-8 bytes when using bcrypt."
        )

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:

    password_bytes = plain_password.encode("utf-8")

    if len(password_bytes) > 72:
        return False

    return pwd_context.verify(
        plain_password,
        hashed_password
    )


# ==================================================
# JWT TOKEN
# ==================================================

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
