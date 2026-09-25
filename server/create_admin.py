import os

from database import Base, engine, SessionLocal
from models import User
from auth import hash_password


# ============================================================
# CREATE DATABASE TABLES
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# ADMIN CONFIGURATION
# ============================================================

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD"
)


if not ADMIN_USERNAME:
    raise RuntimeError(
        "ADMIN_USERNAME environment variable is not set"
    )

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_PASSWORD environment variable is not set"
    )


# ============================================================
# DATABASE TYPE
# ============================================================

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./multiprint_licensing.db"
)

if DATABASE_URL.startswith("postgresql"):
    DATABASE_TYPE = "PostgreSQL"
else:
    DATABASE_TYPE = "SQLite"


print()
print("=" * 60)
print("MULTIPRINT LICENSING - ADMIN CREATION")
print("=" * 60)
print(f"DATABASE : {DATABASE_TYPE}")
print(f"USERNAME : {ADMIN_USERNAME}")
print("=" * 60)


# ============================================================
# CREATE ADMIN
# ============================================================

db = SessionLocal()

try:

    existing_admin = (
        db.query(User)
        .filter(
            User.username == ADMIN_USERNAME
        )
        .first()
    )

    if existing_admin:

        print()
        print("=" * 60)
        print("ADMIN ACCOUNT ALREADY EXISTS")
        print("=" * 60)
        print(f"ID       : {existing_admin.id}")
        print(f"USERNAME : {existing_admin.username}")
        print(f"ADMIN    : {existing_admin.is_admin}")
        print(f"ACTIVE   : {existing_admin.is_active}")
        print("=" * 60)

    else:

        admin = User(
            username=ADMIN_USERNAME,
            password_hash=hash_password(
                ADMIN_PASSWORD
            ),
            is_active=True,
            is_admin=True
        )

        db.add(admin)
        db.commit()
        db.refresh(admin)

        print()
        print("=" * 60)
        print("ADMINISTRATOR CREATED SUCCESSFULLY")
        print("=" * 60)
        print(f"ID       : {admin.id}")
        print(f"USERNAME : {admin.username}")
        print(f"ADMIN    : {admin.is_admin}")
        print(f"ACTIVE   : {admin.is_active}")
        print("=" * 60)

finally:

    db.close()
