import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, ForeignKey, JSON, Index, Enum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base


class Account(Base):
    """Cloud accounts/subscriptions/tenants to crawl."""
    __tablename__ = "accounts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider = Column(String(10), nullable=False)  # "aws" or "azure"
    account_id = Column(String(255), nullable=False)  # AWS account ID or Azure tenant ID
    subscription_id = Column(String(255), nullable=True)  # Azure only
    label = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    identities = relationship("Identity", back_populates="account", cascade="all, delete-orphan")
    crawl_runs = relationship("CrawlRun", back_populates="account", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_accounts_provider", "provider"),
    )


class CrawlRun(Base):
    """Record of each crawl execution."""
    __tablename__ = "crawl_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(UUID(as_uuid=True), ForeignKey("accounts.id"), nullable=False)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(20), default="running")  # running, completed, failed
    identity_count = Column(String(10), default="0")
    error_message = Column(Text, nullable=True)

    account = relationship("Account", back_populates="crawl_runs")
    identities = relationship("Identity", back_populates="crawl_run", cascade="all, delete-orphan")


class Identity(Base):
    """A discovered non-human identity."""
    __tablename__ = "identities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id = Column(UUID(as_uuid=True), ForeignKey("accounts.id"), nullable=False)
    crawl_run_id = Column(UUID(as_uuid=True), ForeignKey("crawl_runs.id"), nullable=False)

    # Core fields
    provider = Column(String(10), nullable=False)  # aws, azure
    identity_type = Column(String(50), nullable=False)  # e.g. iam_role, service_principal, managed_identity
    name = Column(String(512), nullable=False)
    unique_id = Column(String(512), nullable=False)  # ARN (AWS) or objectId (Azure)

    # Classification
    sub_type = Column(String(100), nullable=True)  # e.g. service_linked_role, Application, ManagedIdentity
    is_active = Column(Boolean, default=True)

    # Timestamps from the cloud provider
    cloud_created_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    # Flexible extra data (provider-specific details)
    extra_data = Column(JSON, nullable=True)

    # Local tracking
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    account = relationship("Account", back_populates="identities")
    crawl_run = relationship("CrawlRun", back_populates="identities")
    credentials = relationship("Credential", back_populates="identity", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_identities_provider_type", "provider", "identity_type"),
        Index("ix_identities_account", "account_id"),
        Index("ix_identities_unique_id", "unique_id"),
        Index("ix_identities_crawl_run", "crawl_run_id"),
    )


class Credential(Base):
    """Access keys, secrets, certificates attached to identities."""
    __tablename__ = "credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identity_id = Column(UUID(as_uuid=True), ForeignKey("identities.id"), nullable=False)

    credential_type = Column(String(50), nullable=False)  # access_key, password_credential, certificate, federated
    key_id = Column(String(255), nullable=True)  # AccessKeyId, keyId, etc.
    display_name = Column(String(255), nullable=True)
    status = Column(String(20), nullable=True)  # Active, Inactive
    created_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    # Flexible extra data
    extra_data = Column(JSON, nullable=True)

    discovered_at = Column(DateTime(timezone=True), server_default=func.now())

    identity = relationship("Identity", back_populates="credentials")

    __table_args__ = (
        Index("ix_credentials_identity", "identity_id"),
        Index("ix_credentials_expires", "expires_at"),
    )
