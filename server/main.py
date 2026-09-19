from datetime import datetime, timedelta, timezone
import secrets
import string

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
)
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import Base, engine, SessionLocal
from models import (
    User,
    SoftwareEntitlement,
    Subscription,
    MachineBinding,
)
from auth import (
    verify_password,
    hash_password,
    create_access_token,
)


# ============================================================
# DATABASE
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="MultiPrint Licensing Server",
    description="Licensing and customer management server for MultiPrint",
    version="2.3.0",
)


# ============================================================
# SECURITY
# ============================================================

security = HTTPBearer()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=4, max_length=200)


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateCustomerRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=4, max_length=200)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=4, max_length=200)


class SubscriptionRequest(BaseModel):
    days: int = Field(default=30, ge=1, le=3650)


class MachineActivationRequest(BaseModel):
    machine_id: str = Field(min_length=1, max_length=128)
    computer_name: str | None = Field(default=None, max_length=255)


class AccountStatusRequest(BaseModel):
    is_active: bool


# ============================================================
# HELPERS
# ============================================================

def utc_now():
    return datetime.utcnow()


def generate_license_key():
    alphabet = string.ascii_uppercase + string.digits

    parts = []

    for _ in range(4):
        parts.append(
            "".join(secrets.choice(alphabet) for _ in range(5))
        )

    return "MP-" + "-".join(parts)


def get_user_or_404(
    user_id: int,
    db: Session,
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    return user


# ============================================================
# AUTHENTICATION
# ============================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    try:
        from jose import jwt

        payload = jwt.decode(
            token,
            "CHANGE_THIS_LATER_TO_A_LONG_RANDOM_SECRET",
            algorithms=["HS256"],
        )

        username = payload.get("sub")

        if not username:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token.",
            )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token.",
        )

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is disabled.",
        )

    return user


def get_current_admin(
    current_user: User = Depends(get_current_user),
):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Administrator privileges required.",
        )

    return current_user


# ============================================================
# CUSTOMER STATUS
# ============================================================

def get_customer_status(user: User):
    entitlement = user.software_entitlement
    subscription = user.subscription
    machine = user.machine_binding

    owned = bool(
        entitlement and entitlement.owned
    )

    subscription_active = False
    expiry_date = None

    if subscription:
        expiry_date = subscription.expiry_date

        if (
            subscription.is_active
            and subscription.expiry_date
            and subscription.expiry_date > utc_now()
        ):
            subscription_active = True

    machine_bound = bool(machine)

    return {
        "id": user.id,
        "username": user.username,
        "is_active": bool(user.is_active),
        "is_admin": bool(user.is_admin),

        "owned": owned,
        "software_owned": owned,

        "purchase_date": (
            entitlement.purchase_date.isoformat()
            if entitlement and entitlement.purchase_date
            else None
        ),

        "license_key": (
            entitlement.license_key
            if entitlement
            else None
        ),

        "subscription_active": subscription_active,

        "subscription_start": (
            subscription.start_date.isoformat()
            if subscription and subscription.start_date
            else None
        ),

        "subscription_expiry": (
            expiry_date.isoformat()
            if expiry_date
            else None
        ),

        "machine_bound": machine_bound,

        "machine_id": (
            machine.machine_id
            if machine
            else None
        ),

        "computer_name": (
            machine.computer_name
            if machine
            else None
        ),

        "machine_activated_at": (
            machine.activated_at.isoformat()
            if machine and machine.activated_at
            else None
        ),

        "machine_last_seen": (
            machine.last_seen_at.isoformat()
            if machine and machine.last_seen_at
            else None
        ),
    }


# ============================================================
# BASIC ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "name": "MultiPrint Licensing Server",
        "version": "2.3.0",
        "status": "online",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "MultiPrint Licensing Server",
        "version": "2.3.0",
    }


# ============================================================
# REGISTER
# ============================================================

@app.post("/register")
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
):
    existing = (
        db.query(User)
        .filter(User.username == data.username)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already exists.",
        )

    user = User(
        username=data.username,
        password_hash=hash_password(data.password),
        is_active=True,
        is_admin=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Account created successfully.",
        "user_id": user.id,
        "username": user.username,
    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(
    data: LoginRequest,
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.username == data.username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    if not verify_password(
        data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is disabled.",
        )

    token = create_access_token(
        {
            "sub": user.username,
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "is_admin": bool(user.is_admin),
    }


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/change-password")
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(
        data.current_password,
        current_user.password_hash,
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect.",
        )

    current_user.password_hash = hash_password(
        data.new_password
    )

    db.commit()

    return {
        "message": "Password changed successfully."
    }


# ============================================================
# ADMIN - CREATE CUSTOMER
# ============================================================

@app.post("/admin/users")
def create_customer(
    data: CreateCustomerRequest,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(User)
        .filter(User.username == data.username)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already exists.",
        )

    customer = User(
        username=data.username,
        password_hash=hash_password(data.password),
        is_active=True,
        is_admin=False,
    )

    db.add(customer)
    db.commit()
    db.refresh(customer)

    return {
        "message": "Customer created successfully.",
        "id": customer.id,
        "username": customer.username,
    }


# ============================================================
# ADMIN - CUSTOMER LIST
# ============================================================

@app.get("/admin/customers")
def admin_customers(
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .filter(User.is_admin == False)
        .order_by(User.id.desc())
        .all()
    )

    return [
        get_customer_status(user)
        for user in users
    ]


@app.get("/admin/users")
def admin_users(
    skip: int = 0,
    limit: int = 500,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .filter(User.is_admin == False)
        .order_by(User.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        get_customer_status(user)
        for user in users
    ]


# ============================================================
# ADMIN - CUSTOMER DETAILS
# ============================================================

@app.get("/admin/users/{user_id}")
def admin_user_details(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    if user.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Administrator account cannot be managed here.",
        )

    return get_customer_status(user)


# ============================================================
# ADMIN - CONFIRM PURCHASE
# ============================================================

@app.post("/admin/users/{user_id}/purchase")
def confirm_purchase(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    if user.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Administrator account cannot receive a customer entitlement.",
        )

    entitlement = user.software_entitlement

    if not entitlement:
        entitlement = SoftwareEntitlement(
            user_id=user.id,
            product_name="MultiPrint",
            owned=True,
            purchase_date=utc_now(),
            license_key=generate_license_key(),
        )

        db.add(entitlement)

    else:
        entitlement.owned = True

        if not entitlement.purchase_date:
            entitlement.purchase_date = utc_now()

        if not entitlement.license_key:
            entitlement.license_key = generate_license_key()

    db.commit()
    db.refresh(user)

    return {
        "message": "MultiPrint purchase confirmed.",
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN - ACTIVATE / RENEW SUBSCRIPTION
# ============================================================

@app.post("/admin/users/{user_id}/subscription")
def activate_subscription(
    user_id: int,
    data: SubscriptionRequest,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    if user.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Administrator account cannot receive a subscription.",
        )

    entitlement = user.software_entitlement

    if not entitlement or not entitlement.owned:
        raise HTTPException(
            status_code=400,
            detail="Customer must own MultiPrint before a subscription can be activated.",
        )

    now = utc_now()

    subscription = user.subscription

    if not subscription:
        subscription = Subscription(
            user_id=user.id,
            start_date=now,
            expiry_date=now + timedelta(days=data.days),
            is_active=True,
        )

        db.add(subscription)

    else:
        if (
            subscription.is_active
            and subscription.expiry_date
            and subscription.expiry_date > now
        ):
            base_date = subscription.expiry_date
        else:
            base_date = now

        subscription.start_date = (
            subscription.start_date
            if subscription.start_date
            else now
        )

        subscription.expiry_date = (
            base_date + timedelta(days=data.days)
        )

        subscription.is_active = True

    db.commit()
    db.refresh(user)

    return {
        "message": f"Subscription activated/renewed for {data.days} day(s).",
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN - DEACTIVATE SUBSCRIPTION
# ============================================================

@app.post("/admin/users/{user_id}/subscription/deactivate")
def deactivate_subscription(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    subscription = user.subscription

    if not subscription:
        raise HTTPException(
            status_code=404,
            detail="Customer does not have a subscription.",
        )

    subscription.is_active = False

    db.commit()
    db.refresh(user)

    return {
        "message": "Subscription deactivated.",
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN - MACHINE INFORMATION
# ============================================================

@app.get("/admin/users/{user_id}/machine")
def get_machine_binding(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    machine = user.machine_binding

    if not machine:
        return {
            "bound": False,
            "machine_id": None,
            "computer_name": None,
            "activated_at": None,
            "last_seen_at": None,
        }

    return {
        "bound": True,
        "machine_id": machine.machine_id,
        "computer_name": machine.computer_name,
        "activated_at": (
            machine.activated_at.isoformat()
            if machine.activated_at
            else None
        ),
        "last_seen_at": (
            machine.last_seen_at.isoformat()
            if machine.last_seen_at
            else None
        ),
    }


# ============================================================
# ADMIN - RESET MACHINE
# ============================================================

@app.post("/admin/users/{user_id}/machine/reset")
def reset_machine(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    machine = user.machine_binding

    if not machine:
        return {
            "message": "Customer has no machine binding.",
            "customer": get_customer_status(user),
        }

    db.delete(machine)
    db.commit()
    db.refresh(user)

    return {
        "message": "Machine binding reset successfully.",
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN - ENABLE / DISABLE ACCOUNT
# ============================================================

@app.post("/admin/users/{user_id}/status")
def change_account_status(
    user_id: int,
    data: AccountStatusRequest,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    if user.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Administrator account cannot be disabled here.",
        )

    user.is_active = data.is_active

    db.commit()
    db.refresh(user)

    return {
        "message": (
            "Account enabled."
            if data.is_active
            else "Account disabled."
        ),
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN - DELETE CUSTOMER
# ============================================================

@app.delete("/admin/users/{user_id}")
def delete_customer(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    user = get_user_or_404(
        user_id,
        db,
    )

    if user.is_admin:
        raise HTTPException(
            status_code=400,
            detail="Administrator account cannot be deleted here.",
        )

    db.delete(user)
    db.commit()

    return {
        "message": "Customer deleted successfully."
    }


# ============================================================
# DESKTOP LICENSE STATUS
# ============================================================

@app.get("/license/status")
def license_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.id == current_user.id)
        .first()
    )

    status = get_customer_status(user)

    return {
        "user_id": user.id,
        "username": user.username,

        "is_active": bool(user.is_active),

        "owned": status["owned"],
        "software_owned": status["software_owned"],

        "subscription_active": status["subscription_active"],
        "subscription_start": status["subscription_start"],
        "subscription_expiry": status["subscription_expiry"],

        "machine_bound": status["machine_bound"],
        "machine_id": status["machine_id"],
        "computer_name": status["computer_name"],

        "license_key": status["license_key"],
    }


# ============================================================
# DESKTOP MACHINE ACTIVATION
# ============================================================

@app.post("/license/activate")
def license_activate(
    data: MachineActivationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.id == current_user.id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is disabled.",
        )

    entitlement = user.software_entitlement

    if not entitlement or not entitlement.owned:
        raise HTTPException(
            status_code=403,
            detail="This account does not own MultiPrint.",
        )

    subscription = user.subscription

    if not subscription:
        raise HTTPException(
            status_code=403,
            detail="No active subscription.",
        )

    now = utc_now()

    if (
        not subscription.is_active
        or not subscription.expiry_date
        or subscription.expiry_date <= now
    ):
        raise HTTPException(
            status_code=403,
            detail="Subscription is inactive or expired.",
        )

    machine = user.machine_binding

    if machine:
        if machine.machine_id != data.machine_id:
            raise HTTPException(
                status_code=403,
                detail="This account is already activated on another computer.",
            )

        machine.last_seen_at = now

        if data.computer_name:
            machine.computer_name = data.computer_name

    else:
        machine = MachineBinding(
            user_id=user.id,
            machine_id=data.machine_id,
            computer_name=data.computer_name,
            activated_at=now,
            last_seen_at=now,
        )

        db.add(machine)

    db.commit()
    db.refresh(user)

    return {
        "message": "License activated successfully.",
        "customer": get_customer_status(user),
    }


# ============================================================
# ADMIN DASHBOARD STATS
# ============================================================

@app.get("/admin/dashboard/stats")
def admin_dashboard_stats(
    admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    customers = (
        db.query(User)
        .filter(User.is_admin == False)
        .all()
    )

    total_customers = len(customers)

    purchased = 0
    active_subscriptions = 0
    expired_subscriptions = 0
    machine_bound = 0
    active_accounts = 0

    now = utc_now()

    for customer in customers:

        if customer.is_active:
            active_accounts += 1

        entitlement = customer.software_entitlement

        if entitlement and entitlement.owned:
            purchased += 1

        subscription = customer.subscription

        if subscription:
            if (
                subscription.is_active
                and subscription.expiry_date
                and subscription.expiry_date > now
            ):
                active_subscriptions += 1

            elif (
                subscription.expiry_date
                and subscription.expiry_date <= now
            ):
                expired_subscriptions += 1

        if customer.machine_binding:
            machine_bound += 1

    return {
        "total_customers": total_customers,
        "purchased": purchased,
        "active_subscriptions": active_subscriptions,
        "expired_subscriptions": expired_subscriptions,
        "machine_bound": machine_bound,
        "active_accounts": active_accounts,
    }


# ============================================================
# ADMIN DASHBOARD HTML
# ============================================================

ADMIN_HTML = r"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>MultiPrint Admin</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family:
        Inter,
        Segoe UI,
        Arial,
        sans-serif;

    background: #F5F7FA;
    color: #1F2937;
}

/* =========================================================
   LOGIN
   ========================================================= */

.login-screen {
    position: fixed;
    inset: 0;

    display: flex;
    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #EAF3FF 0%,
            #F5F7FA 50%,
            #FFF4E8 100%
        );

    z-index: 9999;
}

.login-card {
    width: 420px;
    max-width: calc(100% - 32px);

    background: white;

    border-radius: 24px;

    padding: 42px;

    box-shadow:
        0 25px 70px rgba(0, 0, 0, 0.12);
}

.login-logo {
    display: flex;
    justify-content: center;
    margin-bottom: 20px;
}

.login-title {
    text-align: center;

    font-size: 28px;
    font-weight: 800;

    margin-bottom: 8px;

    color: #172033;
}

.login-subtitle {
    text-align: center;

    color: #6B7280;

    margin-bottom: 30px;
}

.login-error {
    display: none;

    padding: 12px 14px;

    background: #FEF2F2;
    color: #B91C1C;

    border-radius: 10px;

    margin-bottom: 18px;

    font-size: 14px;
}

.form-group {
    margin-bottom: 18px;
}

.form-label {
    display: block;

    font-size: 13px;
    font-weight: 700;

    color: #374151;

    margin-bottom: 7px;
}

.form-input {
    width: 100%;

    padding: 13px 14px;

    border: 1px solid #D1D5DB;

    border-radius: 10px;

    outline: none;

    font-size: 14px;

    transition: 0.2s;
}

.form-input:focus {
    border-color: #1976D2;

    box-shadow:
        0 0 0 3px rgba(25, 118, 210, 0.10);
}

.login-button {
    width: 100%;

    border: none;

    border-radius: 11px;

    padding: 14px;

    background: #1976D2;

    color: white;

    font-size: 15px;
    font-weight: 700;

    cursor: pointer;

    transition: 0.2s;
}

.login-button:hover {
    background: #1565C0;
    transform: translateY(-1px);
}

/* =========================================================
   LOGO
   ========================================================= */

.mp-logo {
    display: flex;
    align-items: center;
    gap: 11px;
}

.mp-logo svg {
    width: 48px;
    height: 48px;

    flex-shrink: 0;
}

.mp-logo-text {
    font-size: 24px;
    font-weight: 900;

    letter-spacing: -1px;

    color: #1976D2;
}

.mp-logo-text span {
    color: #F57C00;
}

/* =========================================================
   APPLICATION
   ========================================================= */

.app {
    display: none;

    min-height: 100vh;
}

.sidebar {
    position: fixed;

    left: 0;
    top: 0;
    bottom: 0;

    width: 250px;

    background: #FFFFFF;

    border-right: 1px solid #E5E7EB;

    display: flex;
    flex-direction: column;

    z-index: 100;
}

.sidebar-logo {
    padding: 26px 24px;

    border-bottom: 1px solid #EEF0F3;
}

.nav-section {
    padding: 20px 14px;
}

.nav-label {
    padding: 0 12px 9px;

    font-size: 11px;
    font-weight: 800;

    text-transform: uppercase;

    letter-spacing: 0.08em;

    color: #9CA3AF;
}

.nav-item {
    display: flex;
    align-items: center;

    gap: 12px;

    padding: 12px 14px;

    margin-bottom: 5px;

    border-radius: 10px;

    cursor: pointer;

    color: #6B7280;

    font-size: 14px;
    font-weight: 600;

    transition: 0.2s;
}

.nav-item:hover {
    background: #F3F7FC;

    color: #1976D2;
}

.nav-item.active {
    background: #EAF3FF;

    color: #1976D2;
}

.nav-item span:first-child {
    font-size: 18px;
}

.sidebar-bottom {
    margin-top: auto;

    padding: 14px;

    border-top: 1px solid #EEF0F3;
}

.logout-item:hover {
    background: #FEF2F2;
    color: #DC2626;
}

/* =========================================================
   MAIN
   ========================================================= */

.main {
    margin-left: 250px;

    min-height: 100vh;
}

.topbar {
    height: 72px;

    background: white;

    border-bottom: 1px solid #E5E7EB;

    display: flex;
    align-items: center;
    justify-content: space-between;

    padding: 0 30px;
}

.page-title {
    font-size: 21px;
    font-weight: 800;

    color: #111827;
}

.admin-user {
    display: flex;
    align-items: center;

    gap: 10px;

    color: #4B5563;

    font-size: 13px;
    font-weight: 600;
}

.admin-avatar {
    width: 34px;
    height: 34px;

    border-radius: 50%;

    display: flex;
    align-items: center;
    justify-content: center;

    background: #EAF3FF;

    color: #1976D2;

    font-weight: 800;
}

.content {
    padding: 30px;
}

/* =========================================================
   SECTIONS
   ========================================================= */

.page {
    display: none;
}

.page.active {
    display: block;
}

/* =========================================================
   STAT CARDS
   ========================================================= */

.stats-grid {
    display: grid;

    grid-template-columns:
        repeat(4, minmax(0, 1fr));

    gap: 18px;

    margin-bottom: 24px;
}

.stat-card {
    background: white;

    border: 1px solid #E8EBEF;

    border-radius: 16px;

    padding: 21px;

    box-shadow:
        0 3px 12px rgba(0, 0, 0, 0.035);
}

.stat-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
}

.stat-label {
    font-size: 13px;
    font-weight: 700;

    color: #6B7280;
}

.stat-icon {
    width: 40px;
    height: 40px;

    border-radius: 10px;

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 20px;

    background: #EAF3FF;
}

.stat-value {
    margin-top: 12px;

    font-size: 28px;
    font-weight: 900;

    color: #111827;
}

/* =========================================================
   PANELS
   ========================================================= */

.panel {
    background: white;

    border: 1px solid #E8EBEF;

    border-radius: 16px;

    box-shadow:
        0 3px 12px rgba(0, 0, 0, 0.035);

    overflow: hidden;

    margin-bottom: 22px;
}

.panel-header {
    padding: 20px 22px;

    border-bottom: 1px solid #EEF0F3;

    display: flex;
    align-items: center;
    justify-content: space-between;
}

.panel-title {
    font-size: 16px;
    font-weight: 800;

    color: #111827;
}

.panel-body {
    padding: 22px;
}

/* =========================================================
   BUTTONS
   ========================================================= */

.btn {
    border: none;

    border-radius: 9px;

    padding: 10px 14px;

    font-size: 13px;
    font-weight: 700;

    cursor: pointer;

    transition: 0.2s;
}

.btn:hover {
    transform: translateY(-1px);
}

.btn-primary {
    background: #1976D2;
    color: white;
}

.btn-primary:hover {
    background: #1565C0;
}

.btn-orange {
    background: #F57C00;
    color: white;
}

.btn-orange:hover {
    background: #EF6C00;
}

.btn-success {
    background: #16A34A;
    color: white;
}

.btn-danger {
    background: #DC2626;
    color: white;
}

.btn-warning {
    background: #F59E0B;
    color: white;
}

.btn-secondary {
    background: #EEF2F7;
    color: #374151;
}

.btn-small {
    padding: 7px 10px;
    font-size: 12px;
}

/* =========================================================
   CUSTOMER TABLE
   ========================================================= */

.customer-list {
    width: 100%;
}

.customer-header,
.customer-row {
    display: grid;

    grid-template-columns:
        1.5fr
        0.9fr
        1fr
        1fr
        1fr
        1.5fr;

    gap: 12px;

    align-items: center;
}

.customer-header {
    padding: 12px 20px;

    background: #F9FAFB;

    color: #6B7280;

    font-size: 11px;

    text-transform: uppercase;

    font-weight: 800;

    letter-spacing: 0.04em;
}

.customer-row {
    padding: 15px 20px;

    border-top: 1px solid #EEF0F3;

    font-size: 13px;
}

.customer-row:hover {
    background: #FBFCFE;
}

.customer-name {
    font-weight: 800;

    color: #111827;
}

.muted {
    color: #6B7280;
}

.actions {
    display: flex;

    gap: 5px;

    flex-wrap: wrap;
}

/* =========================================================
   BADGES
   ========================================================= */

.badge {
    display: inline-flex;

    align-items: center;

    padding: 5px 8px;

    border-radius: 999px;

    font-size: 11px;

    font-weight: 800;
}

.badge-green {
    background: #DCFCE7;
    color: #166534;
}

.badge-red {
    background: #FEE2E2;
    color: #991B1B;
}

.badge-orange {
    background: #FFEDD5;
    color: #9A3412;
}

.badge-blue {
    background: #DBEAFE;
    color: #1D4ED8;
}

.badge-gray {
    background: #F3F4F6;
    color: #4B5563;
}

/* =========================================================
   QUICK OVERVIEW
   ========================================================= */

.overview-grid {
    display: grid;

    grid-template-columns:
        repeat(2, minmax(0, 1fr));

    gap: 14px;
}

.overview-customer {
    padding: 15px;

    border: 1px solid #E5E7EB;

    border-radius: 12px;

    background: #FAFBFC;
}

.overview-customer-top {
    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 10px;
}

.overview-customer-name {
    font-weight: 800;

    color: #111827;
}

.overview-meta {
    display: flex;

    flex-wrap: wrap;

    gap: 7px;
}

/* =========================================================
   MODAL
   ========================================================= */

.modal-overlay {
    position: fixed;

    inset: 0;

    background: rgba(17, 24, 39, 0.48);

    display: none;

    align-items: center;
    justify-content: center;

    z-index: 500;

    padding: 20px;
}

.modal-overlay.show {
    display: flex;
}

.modal {
    width: 680px;
    max-width: 100%;

    max-height: 90vh;

    overflow-y: auto;

    background: white;

    border-radius: 18px;

    box-shadow:
        0 30px 80px rgba(0, 0, 0, 0.25);
}

.modal-header {
    padding: 21px 24px;

    border-bottom: 1px solid #EEF0F3;

    display: flex;

    align-items: center;

    justify-content: space-between;
}

.modal-title {
    font-size: 18px;
    font-weight: 900;

    color: #111827;
}

.close-btn {
    border: none;

    background: transparent;

    font-size: 23px;

    color: #6B7280;

    cursor: pointer;
}

.modal-body {
    padding: 24px;
}

.detail-grid {
    display: grid;

    grid-template-columns:
        repeat(2, minmax(0, 1fr));

    gap: 14px;

    margin-bottom: 22px;
}

.detail-item {
    background: #F9FAFB;

    border: 1px solid #EEF0F3;

    border-radius: 11px;

    padding: 13px;
}

.detail-label {
    font-size: 11px;

    text-transform: uppercase;

    letter-spacing: 0.05em;

    font-weight: 800;

    color: #9CA3AF;

    margin-bottom: 5px;
}

.detail-value {
    font-size: 13px;

    font-weight: 700;

    color: #374151;

    word-break: break-word;
}

.modal-section {
    margin-top: 22px;
}

.modal-section-title {
    font-size: 14px;

    font-weight: 900;

    margin-bottom: 12px;

    color: #111827;
}

.subscription-box {
    border: 1px solid #DBEAFE;

    background: #F8FBFF;

    border-radius: 13px;

    padding: 17px;
}

.subscription-actions {
    display: flex;

    flex-wrap: wrap;

    gap: 8px;

    margin-top: 13px;
}

.modal-footer {
    padding: 18px 24px;

    border-top: 1px solid #EEF0F3;

    display: flex;

    justify-content: flex-end;

    gap: 8px;
}

/* =========================================================
   TOAST
   ========================================================= */

.toast {
    position: fixed;

    right: 24px;
    bottom: 24px;

    min-width: 280px;

    max-width: 420px;

    padding: 14px 17px;

    border-radius: 11px;

    background: #111827;

    color: white;

    font-size: 13px;

    font-weight: 600;

    box-shadow:
        0 15px 35px rgba(0, 0, 0, 0.2);

    transform: translateY(120px);

    opacity: 0;

    transition: 0.3s;

    z-index: 1000;
}

.toast.show {
    transform: translateY(0);

    opacity: 1;
}

.toast.success {
    background: #166534;
}

.toast.error {
    background: #991B1B;
}

/* =========================================================
   EMPTY STATE
   ========================================================= */

.empty {
    padding: 35px;

    text-align: center;

    color: #9CA3AF;

    font-size: 14px;
}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media (max-width: 1100px) {

    .stats-grid {
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }

    .customer-header,
    .customer-row {
        grid-template-columns:
            1.5fr
            1fr
            1fr
            1.5fr;
    }

    .customer-header div:nth-child(3),
    .customer-header div:nth-child(4),
    .customer-row > div:nth-child(3),
    .customer-row > div:nth-child(4) {
        display: none;
    }
}

@media (max-width: 800px) {

    .sidebar {
        width: 210px;
    }

    .main {
        margin-left: 210px;
    }

    .overview-grid {
        grid-template-columns: 1fr;
    }
}

@media (max-width: 650px) {

    .sidebar {
        position: relative;

        width: 100%;

        min-height: auto;
    }

    .main {
        margin-left: 0;
    }

    .app {
        display: block;
    }

    .sidebar-bottom {
        margin-top: 0;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }

    .detail-grid {
        grid-template-columns: 1fr;
    }

    .topbar {
        padding: 0 16px;
    }

    .content {
        padding: 16px;
    }

    .customer-header {
        display: none;
    }

    .customer-row {
        grid-template-columns: 1fr;

        padding: 17px;
    }
}

</style>

</head>

<body>

<!-- =======================================================
     LOGIN
     ======================================================= -->

<div id="loginScreen" class="login-screen">

    <div class="login-card">

        <div class="login-logo">

            <div class="mp-logo">

                <svg
                    viewBox="0 0 64 64"
                    xmlns="http://www.w3.org/2000/svg"
                >

                    <!-- orange accent -->
                    <path
                        d="M12 27
                           L20 17
                           H44
                           L52 27"
                        fill="none"
                        stroke="#F57C00"
                        stroke-width="5"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />

                    <!-- printer -->
                    <rect
                        x="10"
                        y="25"
                        width="44"
                        height="25"
                        rx="6"
                        fill="#1976D2"
                    />

                    <!-- paper -->
                    <rect
                        x="19"
                        y="9"
                        width="26"
                        height="22"
                        rx="3"
                        fill="white"
                        stroke="#1976D2"
                        stroke-width="4"
                    />

                    <!-- paper lines -->
                    <path
                        d="M25 16 H39
                           M25 21 H39"
                        stroke="#1976D2"
                        stroke-width="2.5"
                        stroke-linecap="round"
                    />

                    <!-- output -->
                    <rect
                        x="19"
                        y="39"
                        width="26"
                        height="17"
                        rx="3"
                        fill="white"
                    />

                    <!-- status -->
                    <circle
                        cx="46"
                        cy="32"
                        r="3"
                        fill="#F57C00"
                    />

                </svg>

                <div class="mp-logo-text">
                    Multi<span>Print</span>
                </div>

            </div>

        </div>

        <div class="login-title">
            Admin Portal
        </div>

        <div class="login-subtitle">
            MultiPrint Licensing Management
        </div>

        <div
            id="loginError"
            class="login-error"
        ></div>

        <form onsubmit="login(event)">

            <div class="form-group">

                <label class="form-label">
                    Username
                </label>

                <input
                    id="loginUsername"
                    class="form-input"
                    type="text"
                    autocomplete="username"
                    placeholder="Enter username"
                    required
                >

            </div>

            <div class="form-group">

                <label class="form-label">
                    Password
                </label>

                <input
                    id="loginPassword"
                    class="form-input"
                    type="password"
                    autocomplete="current-password"
                    placeholder="Enter password"
                    required
                >

            </div>

            <button
                id="loginButton"
                class="login-button"
                type="submit"
            >
                Login
            </button>

        </form>

    </div>

</div>


<!-- =======================================================
     APPLICATION
     ======================================================= -->

<div id="app" class="app">

    <!-- SIDEBAR -->

    <aside class="sidebar">

        <div class="sidebar-logo">

            <div class="mp-logo">

                <svg
                    viewBox="0 0 64 64"
                    xmlns="http://www.w3.org/2000/svg"
                >

                    <path
                        d="M12 27
                           L20 17
                           H44
                           L52 27"
                        fill="none"
                        stroke="#F57C00"
                        stroke-width="5"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />

                    <rect
                        x="10"
                        y="25"
                        width="44"
                        height="25"
                        rx="6"
                        fill="#1976D2"
                    />

                    <rect
                        x="19"
                        y="9"
                        width="26"
                        height="22"
                        rx="3"
                        fill="white"
                        stroke="#1976D2"
                        stroke-width="4"
                    />

                    <path
                        d="M25 16 H39
                           M25 21 H39"
                        stroke="#1976D2"
                        stroke-width="2.5"
                        stroke-linecap="round"
                    />

                    <rect
                        x="19"
                        y="39"
                        width="26"
                        height="17"
                        rx="3"
                        fill="white"
                    />

                    <circle
                        cx="46"
                        cy="32"
                        r="3"
                        fill="#F57C00"
                    />

                </svg>

                <div class="mp-logo-text">
                    Multi<span>Print</span>
                </div>

            </div>

        </div>

        <div class="nav-section">

            <div class="nav-label">
                Main
            </div>

            <div
                class="nav-item active"
                onclick="showSection('dashboardPage', this)"
            >
                <span>📊</span>
                <span>Dashboard</span>
            </div>

            <div
                class="nav-item"
                onclick="showSection('customersPage', this)"
            >
                <span>👥</span>
                <span>Manage Customers</span>
            </div>

        </div>

        <div class="sidebar-bottom">

            <div
                class="nav-item logout-item"
                onclick="logout()"
            >
                <span>🚪</span>
                <span>Logout</span>
            </div>

        </div>

    </aside>


    <!-- MAIN -->

    <main class="main">

        <div class="topbar">

            <div
                id="pageTitle"
                class="page-title"
            >
                Dashboard
            </div>

            <div class="admin-user">

                <div
                    id="adminUsername"
                >
                    Admin
                </div>

                <div class="admin-avatar">
                    A
                </div>

            </div>

        </div>


        <div class="content">

            <!-- =================================================
                 DASHBOARD
                 ================================================= -->

            <section
                id="dashboardPage"
                class="page active"
            >

                <div class="stats-grid">

                    <div class="stat-card">

                        <div class="stat-top">

                            <div class="stat-label">
                                Total Customers
                            </div>

                            <div class="stat-icon">
                                👥
                            </div>

                        </div>

                        <div
                            id="totalCustomers"
                            class="stat-value"
                        >
                            0
                        </div>

                    </div>


                    <div class="stat-card">

                        <div class="stat-top">

                            <div class="stat-label">
                                Purchased
                            </div>

                            <div class="stat-icon">
                                🛒
                            </div>

                        </div>

                        <div
                            id="purchasedCustomers"
                            class="stat-value"
                        >
                            0
                        </div>

                    </div>


                    <div class="stat-card">

                        <div class="stat-top">

                            <div class="stat-label">
                                Active Subscriptions
                            </div>

                            <div class="stat-icon">
                                🔑
                            </div>

                        </div>

                        <div
                            id="activeSubscriptions"
                            class="stat-value"
                        >
                            0
                        </div>

                    </div>


                    <div class="stat-card">

                        <div class="stat-top">

                            <div class="stat-label">
                                Machine Bound
                            </div>

                            <div class="stat-icon">
                                💻
                            </div>

                        </div>

                        <div
                            id="machineBound"
                            class="stat-value"
                        >
                            0
                        </div>

                    </div>

                </div>


                <!-- QUICK OVERVIEW -->

                <div class="panel">

                    <div class="panel-header">

                        <div class="panel-title">
                            Quick Overview
                        </div>

                        <button
                            class="btn btn-secondary btn-small"
                            onclick="loadDashboard()"
                        >
                            Refresh
                        </button>

                    </div>

                    <div class="panel-body">

                        <div
                            id="quickOverviewCustomers"
                            class="overview-grid"
                        >
                            <div class="empty">
                                Loading customers...
                            </div>
                        </div>

                    </div>

                </div>

            </section>


            <!-- =================================================
                 CUSTOMERS
                 ================================================= -->

            <section
                id="customersPage"
                class="page"
            >

                <div class="panel">

                    <div class="panel-header">

                        <div>

                            <div class="panel-title">
                                Manage Customers
                            </div>

                            <div
                                class="muted"
                                style="margin-top:4px;font-size:12px;"
                            >
                                Manage purchases, subscriptions,
                                machines and customer accounts.
                            </div>

                        </div>

                        <button
                            class="btn btn-primary"
                            onclick="openCreateCustomer()"
                        >
                            + Create Customer
                        </button>

                    </div>

                    <div class="customer-list">

                        <div class="customer-header">

                            <div>Customer</div>
                            <div>Purchase</div>
                            <div>Subscription</div>
                            <div>Machine</div>
                            <div>Account</div>
                            <div>Actions</div>

                        </div>

                        <div id="customerList">

                            <div class="empty">
                                Loading customers...
                            </div>

                        </div>

                    </div>

                </div>

            </section>

        </div>

    </main>

</div>


<!-- =======================================================
     CUSTOMER MODAL
     ======================================================= -->

<div
    id="customerModal"
    class="modal-overlay"
>

    <div class="modal">

        <div class="modal-header">

            <div
                id="customerModalTitle"
                class="modal-title"
            >
                Customer
            </div>

            <button
                class="close-btn"
                onclick="closeModal('customerModal')"
            >
                ×
            </button>

        </div>

        <div class="modal-body">

            <div
                id="customerDetails"
            >
            </div>

        </div>

        <div class="modal-footer">

            <button
                class="btn btn-secondary"
                onclick="closeModal('customerModal')"
            >
                Close
            </button>

        </div>

    </div>

</div>


<!-- =======================================================
     CREATE CUSTOMER MODAL
     ======================================================= -->

<div
    id="createCustomerModal"
    class="modal-overlay"
>

    <div class="modal">

        <div class="modal-header">

            <div class="modal-title">
                Create Customer
            </div>

            <button
                class="close-btn"
                onclick="closeModal('createCustomerModal')"
            >
                ×
            </button>

        </div>

        <div class="modal-body">

            <div class="form-group">

                <label class="form-label">
                    Username
                </label>

                <input
                    id="newUsername"
                    class="form-input"
                    placeholder="Customer username"
                >

            </div>

            <div class="form-group">

                <label class="form-label">
                    Password
                </label>

                <input
                    id="newPassword"
                    class="form-input"
                    type="password"
                    placeholder="Customer password"
                >

            </div>

        </div>

        <div class="modal-footer">

            <button
                class="btn btn-secondary"
                onclick="closeModal('createCustomerModal')"
            >
                Cancel
            </button>

            <button
                class="btn btn-primary"
                onclick="createCustomer()"
            >
                Create Customer
            </button>

        </div>

    </div>

</div>


<!-- =======================================================
     SUBSCRIPTION MODAL
     ======================================================= -->

<div
    id="subscriptionModal"
    class="modal-overlay"
>

    <div class="modal">

        <div class="modal-header">

            <div class="modal-title">
                Activate / Renew Subscription
            </div>

            <button
                class="close-btn"
                onclick="closeModal('subscriptionModal')"
            >
                ×
            </button>

        </div>

        <div class="modal-body">

            <div
                id="subscriptionCustomerName"
                style="
                    font-weight:800;
                    margin-bottom:18px;
                "
            >
            </div>

            <div class="form-group">

                <label class="form-label">
                    Subscription Duration
                </label>

                <select
                    id="subscriptionDays"
                    class="form-input"
                >

                    <option value="7">
                        7 Days
                    </option>

                    <option
                        value="30"
                        selected
                    >
                        30 Days
                    </option>

                    <option value="60">
                        60 Days
                    </option>

                    <option value="90">
                        90 Days
                    </option>

                    <option value="180">
                        180 Days
                    </option>

                    <option value="365">
                        1 Year
                    </option>

                    <option value="730">
                        2 Years
                    </option>

                </select>

            </div>

        </div>

        <div class="modal-footer">

            <button
                class="btn btn-secondary"
                onclick="closeModal('subscriptionModal')"
            >
                Cancel
            </button>

            <button
                class="btn btn-orange"
                onclick="submitSubscription()"
            >
                Activate / Renew
            </button>

        </div>

    </div>

</div>


<!-- =======================================================
     TOAST
     ======================================================= -->

<div
    id="toast"
    class="toast"
>
</div>


<script>

/* ==========================================================
   GLOBALS
   ========================================================== */

let token = sessionStorage.getItem(
    "multiprint_admin_token"
);

let currentCustomer = null;

let toastTimer = null;


/* ==========================================================
   API REQUEST
   ========================================================== */

async function apiRequest(
    url,
    options = {}
) {

    const headers = {
        ...(options.headers || {})
    };

    if (token) {
        headers["Authorization"] =
            "Bearer " + token;
    }

    if (
        options.body &&
        !headers["Content-Type"]
    ) {
        headers["Content-Type"] =
            "application/json";
    }

    const response = await fetch(
        url,
        {
            ...options,
            headers
        }
    );

    let data = {};

    try {
        data = await response.json();
    }
    catch (e) {
        data = {};
    }

    if (!response.ok) {

        if (
            response.status === 401 ||
            response.status === 403
        ) {

            if (
                response.status === 401
            ) {
                logout(false);
            }
        }

        throw new Error(
            data.detail ||
            "Request failed."
        );
    }

    return data;
}


/* ==========================================================
   TOAST
   ========================================================== */

function showToast(
    message,
    type = "success"
) {

    const toast =
        document.getElementById("toast");

    toast.textContent = message;

    toast.className =
        "toast show " + type;

    clearTimeout(toastTimer);

    toastTimer = setTimeout(
        () => {
            toast.className = "toast";
        },
        3500
    );
}


/* ==========================================================
   LOGIN
   ========================================================== */

async function login(event) {

    event.preventDefault();

    const username =
        document.getElementById(
            "loginUsername"
        ).value.trim();

    const password =
        document.getElementById(
            "loginPassword"
        ).value;

    const errorBox =
        document.getElementById(
            "loginError"
        );

    const button =
        document.getElementById(
            "loginButton"
        );

    errorBox.style.display = "none";

    button.disabled = true;

    button.textContent = "Logging in...";

    try {

        const response =
            await fetch(
                "/login",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        username,
                        password
                    })
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail ||
                "Invalid login."
            );
        }

        if (!data.is_admin) {
            throw new Error(
                "This account is not an administrator."
            );
        }

        token =
            data.access_token;

        sessionStorage.setItem(
            "multiprint_admin_token",
            token
        );

        document.getElementById(
            "adminUsername"
        ).textContent =
            data.username;

        document.getElementById(
            "loginScreen"
        ).style.display = "none";

        document.getElementById(
            "app"
        ).style.display = "block";

        await loadDashboard();

        await loadCustomers();

        showToast(
            "Welcome to MultiPrint Admin."
        );

    }
    catch (error) {

        errorBox.textContent =
            error.message;

        errorBox.style.display =
            "block";

    }
    finally {

        button.disabled = false;

        button.textContent = "Login";
    }
}


/* ==========================================================
   LOGOUT
   ========================================================== */

function logout(
    showMessage = true
) {

    sessionStorage.removeItem(
        "multiprint_admin_token"
    );

    token = null;

    document.getElementById(
        "app"
    ).style.display = "none";

    document.getElementById(
        "loginScreen"
    ).style.display = "flex";

    document.getElementById(
        "loginPassword"
    ).value = "";

    document.getElementById(
        "loginError"
    ).style.display = "none";

    if (showMessage) {

        showToast(
            "You have been logged out."
        );
    }
}


/* ==========================================================
   INITIALIZE
   ========================================================== */

async function initialize() {

    if (!token) {

        document.getElementById(
            "loginScreen"
        ).style.display = "flex";

        return;
    }

    try {

        const stats =
            await apiRequest(
                "/admin/dashboard/stats"
            );

        document.getElementById(
            "loginScreen"
        ).style.display = "none";

        document.getElementById(
            "app"
        ).style.display = "block";

        await loadDashboard();

        await loadCustomers();

    }
    catch (error) {

        logout(false);
    }
}


/* ==========================================================
   SECTION NAVIGATION
   ========================================================== */

function showSection(
    pageId,
    element
) {

    document
        .querySelectorAll(".page")
        .forEach(
            page => {
                page.classList.remove(
                    "active"
                );
            }
        );

    document
        .getElementById(pageId)
        .classList.add("active");

    document
        .querySelectorAll(".nav-item")
        .forEach(
            item => {
                item.classList.remove(
                    "active"
                );
            }
        );

    if (element) {
        element.classList.add(
            "active"
        );
    }

    const title =
        pageId === "customersPage"
            ? "Manage Customers"
            : "Dashboard";

    document.getElementById(
        "pageTitle"
    ).textContent = title;

    if (
        pageId === "customersPage"
    ) {
        loadCustomers();
    }
}


/* ==========================================================
   DASHBOARD
   ========================================================== */

async function loadDashboard() {

    try {

        const data =
            await apiRequest(
                "/admin/dashboard/stats"
            );

        document.getElementById(
            "totalCustomers"
        ).textContent =
            data.total_customers || 0;

        document.getElementById(
            "purchasedCustomers"
        ).textContent =
            data.purchased || 0;

        document.getElementById(
            "activeSubscriptions"
        ).textContent =
            data.active_subscriptions || 0;

        document.getElementById(
            "machineBound"
        ).textContent =
            data.machine_bound || 0;

        await loadQuickOverviewCustomers();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   QUICK OVERVIEW
   ========================================================== */

async function loadQuickOverviewCustomers() {

    const container =
        document.getElementById(
            "quickOverviewCustomers"
        );

    try {

        const data =
            await apiRequest(
                "/admin/users?limit=500"
            );

        if (!data.length) {

            container.innerHTML =
                `
                <div class="empty">
                    No customers yet.
                </div>
                `;

            return;
        }

        container.innerHTML =
            data
                .slice(0, 10)
                .map(customer => {

                    let subscriptionBadge =
                        customer.subscription_active
                            ? `
                              <span class="badge badge-green">
                                Active
                              </span>
                              `
                            : `
                              <span class="badge badge-gray">
                                No Active Subscription
                              </span>
                              `;

                    let purchaseBadge =
                        customer.owned
                            ? `
                              <span class="badge badge-blue">
                                Purchased
                              </span>
                              `
                            : `
                              <span class="badge badge-orange">
                                Not Purchased
                              </span>
                              `;

                    let machineBadge =
                        customer.machine_bound
                            ? `
                              <span class="badge badge-green">
                                Machine Bound
                              </span>
                              `
                            : `
                              <span class="badge badge-gray">
                                Not Bound
                              </span>
                              `;

                    return `
                        <div
                            class="overview-customer"
                        >

                            <div
                                class="overview-customer-top"
                            >

                                <div
                                    class="overview-customer-name"
                                >
                                    ${escapeHtml(
                                        customer.username
                                    )}
                                </div>

                                <span
                                    class="badge ${
                                        customer.is_active
                                            ? "badge-green"
                                            : "badge-red"
                                    }"
                                >
                                    ${
                                        customer.is_active
                                            ? "Enabled"
                                            : "Disabled"
                                    }
                                </span>

                            </div>

                            <div
                                class="overview-meta"
                            >
                                ${purchaseBadge}
                                ${subscriptionBadge}
                                ${machineBadge}
                            </div>

                        </div>
                    `;

                })
                .join("");

    }
    catch (error) {

        container.innerHTML =
            `
            <div class="empty">
                Unable to load customers.
            </div>
            `;
    }
}


/* ==========================================================
   CUSTOMERS
   ========================================================== */

async function loadCustomers() {

    const container =
        document.getElementById(
            "customerList"
        );

    container.innerHTML =
        `
        <div class="empty">
            Loading customers...
        </div>
        `;

    try {

        const customers =
            await apiRequest(
                "/admin/users?limit=500"
            );

        if (!customers.length) {

            container.innerHTML =
                `
                <div class="empty">
                    No customers found.
                </div>
                `;

            return;
        }

        container.innerHTML =
            customers
                .map(customer =>
                    customerRow(customer)
                )
                .join("");

    }
    catch (error) {

        container.innerHTML =
            `
            <div class="empty">
                ${escapeHtml(
                    error.message
                )}
            </div>
            `;

    }
}


/* ==========================================================
   CUSTOMER ROW
   ========================================================== */

function customerRow(
    customer
) {

    const purchase =
        customer.owned
            ? `
              <span class="badge badge-green">
                Purchased
              </span>
              `
            : `
              <span class="badge badge-orange">
                Not Purchased
              </span>
              `;

    const subscription =
        customer.subscription_active
            ? `
              <span class="badge badge-green">
                Active
              </span>
              `
            : `
              <span class="badge badge-gray">
                Inactive
              </span>
              `;

    const machine =
        customer.machine_bound
            ? `
              <span class="badge badge-blue">
                Bound
              </span>
              `
            : `
              <span class="badge badge-gray">
                None
              </span>
              `;

    const account =
        customer.is_active
            ? `
              <span class="badge badge-green">
                Enabled
              </span>
              `
            : `
              <span class="badge badge-red">
                Disabled
              </span>
              `;

    return `
        <div class="customer-row">

            <div>
                <div class="customer-name">
                    ${escapeHtml(
                        customer.username
                    )}
                </div>

                <div class="muted">
                    ID: ${customer.id}
                </div>
            </div>

            <div>
                ${purchase}
            </div>

            <div>
                ${subscription}
            </div>

            <div>
                ${machine}
            </div>

            <div>
                ${account}
            </div>

            <div class="actions">

                <button
                    class="btn btn-secondary btn-small"
                    onclick="openCustomer(${customer.id})"
                >
                    Manage
                </button>

            </div>

        </div>
    `;
}


/* ==========================================================
   OPEN CUSTOMER
   ========================================================== */

async function openCustomer(
    customerId
) {

    try {

        const customer =
            await apiRequest(
                `/admin/users/${customerId}`
            );

        currentCustomer = customer;

        document.getElementById(
            "customerModalTitle"
        ).textContent =
            "Manage: " +
            customer.username;

        renderCustomerDetails(
            customer
        );

        document.getElementById(
            "customerModal"
        ).classList.add("show");

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   CUSTOMER DETAILS
   ========================================================== */

function renderCustomerDetails(
    customer
) {

    const purchaseText =
        customer.owned
            ? "Purchased"
            : "Not Purchased";

    const subscriptionText =
        customer.subscription_active
            ? "Active"
            : "Inactive";

    const machineText =
        customer.machine_bound
            ? "Bound"
            : "Not Bound";

    const expiry =
        customer.subscription_expiry
            ? formatDate(
                customer.subscription_expiry
            )
            : "—";

    const machineId =
        customer.machine_id || "—";

    const computerName =
        customer.computer_name || "—";

    let html = `

        <div class="detail-grid">

            <div class="detail-item">

                <div class="detail-label">
                    Username
                </div>

                <div class="detail-value">
                    ${escapeHtml(
                        customer.username
                    )}
                </div>

            </div>


            <div class="detail-item">

                <div class="detail-label">
                    Customer ID
                </div>

                <div class="detail-value">
                    ${customer.id}
                </div>

            </div>


            <div class="detail-item">

                <div class="detail-label">
                    Account
                </div>

                <div class="detail-value">

                    <span
                        class="badge ${
                            customer.is_active
                                ? "badge-green"
                                : "badge-red"
                        }"
                    >
                        ${
                            customer.is_active
                                ? "Enabled"
                                : "Disabled"
                        }
                    </span>

                </div>

            </div>


            <div class="detail-item">

                <div class="detail-label">
                    Software Ownership
                </div>

                <div class="detail-value">

                    <span
                        class="badge ${
                            customer.owned
                                ? "badge-green"
                                : "badge-orange"
                        }"
                    >
                        ${purchaseText}
                    </span>

                </div>

            </div>


            <div class="detail-item">

                <div class="detail-label">
                    License Key
                </div>

                <div class="detail-value">
                    ${escapeHtml(
                        customer.license_key || "—"
                    )}
                </div>

            </div>


            <div class="detail-item">

                <div class="detail-label">
                    Purchase Date
                </div>

                <div class="detail-value">
                    ${
                        customer.purchase_date
                            ? formatDate(
                                customer.purchase_date
                            )
                            : "—"
                    }
                </div>

            </div>

        </div>


        <!-- SUBSCRIPTION -->

        <div class="modal-section">

            <div class="modal-section-title">
                Subscription
            </div>

            <div class="subscription-box">

                <div
                    class="detail-grid"
                    style="margin-bottom:0;"
                >

                    <div class="detail-item">

                        <div class="detail-label">
                            Status
                        </div>

                        <div class="detail-value">

                            <span
                                class="badge ${
                                    customer.subscription_active
                                        ? "badge-green"
                                        : "badge-red"
                                }"
                            >
                                ${subscriptionText}
                            </span>

                        </div>

                    </div>


                    <div class="detail-item">

                        <div class="detail-label">
                            Expiry
                        </div>

                        <div class="detail-value">
                            ${expiry}
                        </div>

                    </div>

                </div>


                <div class="subscription-actions">

                    ${
                        customer.owned
                            ? `
                            <button
                                class="btn btn-orange"
                                onclick="openSubscriptionModal(${customer.id})"
                            >
                                ${
                                    customer.subscription_active
                                        ? "Renew Subscription"
                                        : "Activate Subscription"
                                }
                            </button>
                            `
                            : `
                            <button
                                class="btn btn-secondary"
                                disabled
                                title="Purchase must be confirmed first"
                            >
                                Activate Subscription
                            </button>
                            `
                    }


                    ${
                        customer.subscription_active
                            ? `
                            <button
                                class="btn btn-danger"
                                onclick="deactivateSubscription(${customer.id})"
                            >
                                Deactivate Subscription
                            </button>
                            `
                            : ""
                    }

                </div>

                ${
                    !customer.owned
                        ? `
                        <div
                            style="
                                margin-top:12px;
                                font-size:12px;
                                color:#9A3412;
                            "
                        >
                            Confirm the customer's
                            MultiPrint purchase before
                            activating a subscription.
                        </div>
                        `
                        : ""
                }

            </div>

        </div>


        <!-- MACHINE -->

        <div class="modal-section">

            <div class="modal-section-title">
                Machine Binding
            </div>

            <div class="detail-grid">

                <div class="detail-item">

                    <div class="detail-label">
                        Status
                    </div>

                    <div class="detail-value">

                        <span
                            class="badge ${
                                customer.machine_bound
                                    ? "badge-green"
                                    : "badge-gray"
                            }"
                        >
                            ${machineText}
                        </span>

                    </div>

                </div>


                <div class="detail-item">

                    <div class="detail-label">
                        Computer Name
                    </div>

                    <div class="detail-value">
                        ${escapeHtml(
                            computerName
                        )}
                    </div>

                </div>


                <div class="detail-item"
                     style="grid-column:1/-1;">

                    <div class="detail-label">
                        Machine ID
                    </div>

                    <div class="detail-value">
                        ${escapeHtml(
                            machineId
                        )}
                    </div>

                </div>

            </div>

            ${
                customer.machine_bound
                    ? `
                    <button
                        class="btn btn-warning"
                        onclick="resetMachine(${customer.id})"
                    >
                        Reset Machine Binding
                    </button>
                    `
                    : `
                    <div
                        class="muted"
                        style="font-size:12px;"
                    >
                        No machine is currently bound
                        to this customer.
                    </div>
                    `
            }

        </div>


        <!-- ACCOUNT -->

        <div class="modal-section">

            <div class="modal-section-title">
                Account Controls
            </div>

            <div class="subscription-actions">

                ${
                    customer.is_active
                        ? `
                        <button
                            class="btn btn-warning"
                            onclick="toggleAccount(${customer.id}, false)"
                        >
                            Disable Account
                        </button>
                        `
                        : `
                        <button
                            class="btn btn-success"
                            onclick="toggleAccount(${customer.id}, true)"
                        >
                            Enable Account
                        </button>
                        `
                }


                <button
                    class="btn btn-danger"
                    onclick="deleteCustomer(${customer.id})"
                >
                    Delete Customer
                </button>

            </div>

        </div>


        <!-- PURCHASE -->

        <div class="modal-section">

            <div class="modal-section-title">
                Purchase Management
            </div>

            ${
                customer.owned
                    ? `
                    <div
                        style="
                            padding:13px;
                            background:#F0FDF4;
                            border:1px solid #BBF7D0;
                            border-radius:10px;
                            color:#166534;
                            font-size:13px;
                            font-weight:700;
                        "
                    >
                        MultiPrint purchase is confirmed.
                    </div>
                    `
                    : `
                    <button
                        class="btn btn-primary"
                        onclick="confirmPurchase(${customer.id})"
                    >
                        Confirm MultiPrint Purchase
                    </button>
                    `
            }

        </div>
    `;

    document.getElementById(
        "customerDetails"
    ).innerHTML = html;
}


/* ==========================================================
   PURCHASE
   ========================================================== */

async function confirmPurchase(
    customerId
) {

    if (
        !confirm(
            "Confirm that this customer has purchased MultiPrint?"
        )
    ) {
        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}/purchase`,
            {
                method: "POST"
            }
        );

        showToast(
            "Purchase confirmed successfully."
        );

        await refreshCustomer(
            customerId
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   OPEN SUBSCRIPTION MODAL
   ========================================================== */

async function openSubscriptionModal(
    customerId
) {

    try {

        const customer =
            await apiRequest(
                `/admin/users/${customerId}`
            );

        currentCustomer = customer;

        document.getElementById(
            "subscriptionCustomerName"
        ).textContent =
            "Customer: " +
            customer.username;

        document.getElementById(
            "subscriptionModal"
        ).dataset.customerId =
            customerId;

        document.getElementById(
            "subscriptionModal"
        ).classList.add("show");

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   ACTIVATE / RENEW SUBSCRIPTION
   ========================================================== */

async function submitSubscription() {

    const modal =
        document.getElementById(
            "subscriptionModal"
        );

    const customerId =
        modal.dataset.customerId;

    const days =
        parseInt(
            document.getElementById(
                "subscriptionDays"
            ).value
        );

    if (!customerId) {

        showToast(
            "Customer ID is missing.",
            "error"
        );

        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}/subscription`,
            {
                method: "POST",

                body: JSON.stringify({
                    days
                })
            }
        );

        closeModal(
            "subscriptionModal"
        );

        showToast(
            `Subscription activated/renewed for ${days} days.`
        );

        await refreshCustomer(
            parseInt(customerId)
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   DEACTIVATE SUBSCRIPTION
   ========================================================== */

async function deactivateSubscription(
    customerId
) {

    if (
        !confirm(
            "Deactivate this customer's subscription?"
        )
    ) {
        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}/subscription/deactivate`,
            {
                method: "POST"
            }
        );

        showToast(
            "Subscription deactivated."
        );

        await refreshCustomer(
            customerId
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   RESET MACHINE
   ========================================================== */

async function resetMachine(
    customerId
) {

    if (
        !confirm(
            "Reset this machine binding? The customer will be able to activate on another computer."
        )
    ) {
        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}/machine/reset`,
            {
                method: "POST"
            }
        );

        showToast(
            "Machine binding reset successfully."
        );

        await refreshCustomer(
            customerId
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   ACCOUNT ENABLE / DISABLE
   ========================================================== */

async function toggleAccount(
    customerId,
    enabled
) {

    const action =
        enabled
            ? "enable"
            : "disable";

    if (
        !confirm(
            `Are you sure you want to ${action} this account?`
        )
    ) {
        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}/status`,
            {
                method: "POST",

                body: JSON.stringify({
                    is_active: enabled
                })
            }
        );

        showToast(
            enabled
                ? "Account enabled."
                : "Account disabled."
        );

        await refreshCustomer(
            customerId
        );

        await loadCustomers();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   DELETE CUSTOMER
   ========================================================== */

async function deleteCustomer(
    customerId
) {

    if (
        !confirm(
            "Delete this customer permanently? This cannot be undone."
        )
    ) {
        return;
    }

    try {

        await apiRequest(
            `/admin/users/${customerId}`,
            {
                method: "DELETE"
            }
        );

        closeModal(
            "customerModal"
        );

        showToast(
            "Customer deleted successfully."
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   REFRESH CUSTOMER
   ========================================================== */

async function refreshCustomer(
    customerId
) {

    const customer =
        await apiRequest(
            `/admin/users/${customerId}`
        );

    currentCustomer = customer;

    renderCustomerDetails(
        customer
    );
}


/* ==========================================================
   CREATE CUSTOMER
   ========================================================== */

function openCreateCustomer() {

    document.getElementById(
        "newUsername"
    ).value = "";

    document.getElementById(
        "newPassword"
    ).value = "";

    document.getElementById(
        "createCustomerModal"
    ).classList.add("show");
}


async function createCustomer() {

    const username =
        document.getElementById(
            "newUsername"
        ).value.trim();

    const password =
        document.getElementById(
            "newPassword"
        ).value;

    if (!username || !password) {

        showToast(
            "Username and password are required.",
            "error"
        );

        return;
    }

    try {

        await apiRequest(
            "/admin/users",
            {
                method: "POST",

                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        closeModal(
            "createCustomerModal"
        );

        showToast(
            "Customer created successfully."
        );

        await loadCustomers();

        await loadDashboard();

    }
    catch (error) {

        showToast(
            error.message,
            "error"
        );
    }
}


/* ==========================================================
   MODAL
   ========================================================== */

function closeModal(
    modalId
) {

    document
        .getElementById(modalId)
        .classList.remove("show");
}


/* ==========================================================
   DATE FORMAT
   ========================================================== */

function formatDate(
    value
) {

    if (!value) {
        return "—";
    }

    try {

        const date =
            new Date(value);

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return value;
        }

        return date.toLocaleString();

    }
    catch (e) {

        return value;
    }
}


/* ==========================================================
   HTML ESCAPE
   ========================================================== */

function escapeHtml(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


/* ==========================================================
   MODAL CLICK OUTSIDE
   ========================================================== */

document
    .querySelectorAll(".modal-overlay")
    .forEach(modal => {

        modal.addEventListener(
            "click",
            function(event) {

                if (
                    event.target === modal
                ) {
                    modal.classList.remove(
                        "show"
                    );
                }

            }
        );

    });


/* ==========================================================
   START
   ========================================================== */

initialize();

</script>

</body>

</html>
"""


# ============================================================
# ADMIN DASHBOARD ROUTE
# ============================================================

@app.get(
    "/admin/dashboard",
    response_class=HTMLResponse,
)
def admin_dashboard_page():

    return HTMLResponse(
        content=ADMIN_HTML
    )