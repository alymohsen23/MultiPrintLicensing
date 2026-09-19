from database import Base, engine, SessionLocal
from models import (
    User,
    SoftwareEntitlement,
    Subscription,
    MachineBinding
)
from auth import hash_password


# ============================================================
# CREATE DATABASE TABLES
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# ADMIN ACCOUNT
# ============================================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


# ============================================================
# CREATE ADMIN
# ============================================================

db = SessionLocal()

try:

    existing_admin = (
        db.query(User)
        .filter(User.username == ADMIN_USERNAME)
        .first()
    )

    if existing_admin:

        print()
        print("=" * 50)
        print("ADMIN ACCOUNT ALREADY EXISTS")
        print("=" * 50)
        print(f"ID       : {existing_admin.id}")
        print(f"USERNAME : {existing_admin.username}")
        print(f"ADMIN    : {existing_admin.is_admin}")
        print(f"ACTIVE   : {existing_admin.is_active}")
        print("=" * 50)

    else:

        admin = User(
            username=ADMIN_USERNAME,
            password_hash=hash_password(ADMIN_PASSWORD),
            is_active=True,
            is_admin=True
        )

        db.add(admin)
        db.commit()
        db.refresh(admin)

        print()
        print("=" * 50)
        print("ADMINISTRATOR CREATED SUCCESSFULLY")
        print("=" * 50)
        print(f"ID       : {admin.id}")
        print(f"USERNAME : {admin.username}")
        print(f"PASSWORD : {ADMIN_PASSWORD}")
        print(f"ADMIN    : {admin.is_admin}")
        print(f"ACTIVE   : {admin.is_active}")
        print("=" * 50)

finally:

    db.close()