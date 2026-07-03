import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id:            Mapped[str]      = mapped_column(String(36), primary_key=True, default=_uuid)
    full_name:     Mapped[str]      = mapped_column(String(100), nullable=False)
    email:         Mapped[str]      = mapped_column(String(254), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str]   = mapped_column(String(128), nullable=False)
    is_active:     Mapped[bool]     = mapped_column(Boolean, default=True, nullable=False)
    is_verified:   Mapped[bool]     = mapped_column(Boolean, default=False, nullable=False)
    plan:          Mapped[str]      = mapped_column(String(20), default="starter", nullable=False)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at:    Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    scans:         Mapped[list["Scan"]]         = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    subscriptions: Mapped[list["Subscription"]] = relationship("Subscription", back_populates="user", cascade="all, delete-orphan")
    api_keys:      Mapped[list["APIKey"]]       = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

    @property
    def plan_display(self) -> str:
        return self.plan.capitalize()


# ─────────────────────────────────────────────────────────────────────────────
class Subscription(Base):
    __tablename__ = "subscriptions"

    id:                  Mapped[str]            = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:             Mapped[str]            = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    stripe_subscription_id: Mapped[str | None]  = mapped_column(String(64), unique=True, nullable=True)
    stripe_price_id:     Mapped[str | None]     = mapped_column(String(64), nullable=True)
    plan:                Mapped[str]            = mapped_column(String(20), nullable=False)
    billing_cycle:       Mapped[str]            = mapped_column(String(10), default="monthly", nullable=False)
    status:              Mapped[str]            = mapped_column(String(20), default="active", nullable=False)
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end:   Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool]          = mapped_column(Boolean, default=False, nullable=False)
    created_at:          Mapped[datetime]       = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="subscriptions")


# ─────────────────────────────────────────────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id:               Mapped[str]           = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:          Mapped[str]           = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    chart_name:       Mapped[str]           = mapped_column(String(255), nullable=False)
    label:            Mapped[str | None]    = mapped_column(String(80), nullable=True)
    original_filename: Mapped[str]         = mapped_column(String(255), nullable=False)
    file_path:        Mapped[str | None]    = mapped_column(String(512), nullable=True)
    file_size:        Mapped[int]           = mapped_column(Integer, default=0, nullable=False)
    min_severity:     Mapped[str]           = mapped_column(String(10), default="MEDIUM", nullable=False)
    status:           Mapped[str]           = mapped_column(String(20), default="pending", nullable=False)
    risk_score:       Mapped[int | None]    = mapped_column(Integer, nullable=True)
    findings_count:   Mapped[int]           = mapped_column(Integer, default=0, nullable=False)
    error_message:    Mapped[str | None]    = mapped_column(Text, nullable=True)
    started_at:       Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at:       Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    user:     Mapped["User"]           = relationship("User", back_populates="scans")
    findings: Mapped[list["Finding"]]  = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    @property
    def file_size_display(self) -> str:
        b = self.file_size
        if b < 1024:         return f"{b} B"
        if b < 1_048_576:    return f"{b/1024:.1f} KB"
        return               f"{b/1_048_576:.1f} MB"


# ─────────────────────────────────────────────────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id:           Mapped[str]        = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id:      Mapped[str]        = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    severity:     Mapped[str]        = mapped_column(String(10), nullable=False, index=True)  # CRITICAL/HIGH/MEDIUM/LOW
    title:        Mapped[str]        = mapped_column(String(255), nullable=False)
    description:  Mapped[str]        = mapped_column(Text, nullable=False)
    location:     Mapped[str | None] = mapped_column(String(512), nullable=True)
    remediation:  Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_command:  Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_score:   Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_id:       Mapped[str | None] = mapped_column(String(20), nullable=True)
    check_id:     Mapped[str]        = mapped_column(String(50), nullable=False)
    created_at:   Mapped[datetime]   = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


# ─────────────────────────────────────────────────────────────────────────────
class APIKey(Base):
    __tablename__ = "api_keys"

    id:          Mapped[str]           = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:     Mapped[str]           = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name:        Mapped[str]           = mapped_column(String(80), nullable=False)
    key_hash:    Mapped[str]           = mapped_column(String(128), nullable=False, unique=True)
    key_prefix:  Mapped[str]           = mapped_column(String(8), nullable=False)
    is_active:   Mapped[bool]          = mapped_column(Boolean, default=True, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at:  Mapped[datetime]      = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    expires_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="api_keys")


# ─────────────────────────────────────────────────────────────────────────────
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id:         Mapped[str]      = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id:    Mapped[str]      = mapped_column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str]      = mapped_column(String(128), nullable=False, unique=True)
    is_revoked: Mapped[bool]     = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
