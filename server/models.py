from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base


# ============================================================
# USER
# ============================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    is_admin = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # --------------------------------------------------------
    # SOFTWARE ENTITLEMENT
    # --------------------------------------------------------

    software_entitlement = relationship(
        "SoftwareEntitlement",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # --------------------------------------------------------
    # SUBSCRIPTION
    # --------------------------------------------------------

    subscription = relationship(
        "Subscription",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # --------------------------------------------------------
    # MACHINE BINDING
    # --------------------------------------------------------

    machine_binding = relationship(
        "MachineBinding",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )


# ============================================================
# SOFTWARE ENTITLEMENT
# ============================================================

class SoftwareEntitlement(Base):
    __tablename__ = "software_entitlements"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        unique=True,
        nullable=False
    )

    product_name = Column(
        String,
        default="MultiPrint",
        nullable=False
    )

    owned = Column(
        Boolean,
        default=False,
        nullable=False
    )

    purchase_date = Column(
        DateTime,
        nullable=True
    )

    license_key = Column(
        String,
        nullable=True,
        unique=True
    )

    user = relationship(
        "User",
        back_populates="software_entitlement"
    )


# ============================================================
# SUBSCRIPTION
# ============================================================

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        unique=True,
        nullable=False
    )

    start_date = Column(
        DateTime,
        nullable=True
    )

    expiry_date = Column(
        DateTime,
        nullable=True
    )

    is_active = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    user = relationship(
        "User",
        back_populates="subscription"
    )


# ============================================================
# MACHINE BINDING
# ============================================================

class MachineBinding(Base):
    """
    One-and-only-one Windows computer binding per customer.

    A customer can have only one registered computer.
    """

    __tablename__ = "machine_bindings"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        unique=True,
        nullable=False
    )

    machine_id = Column(
        String(128),
        nullable=False
    )

    computer_name = Column(
        String(255),
        nullable=True
    )

    activated_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    last_seen_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    user = relationship(
        "User",
        back_populates="machine_binding"
    )