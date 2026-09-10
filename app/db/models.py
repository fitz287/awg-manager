from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, BigInteger
from sqlalchemy.orm import relationship
from app.db.database import Base

class InterfaceModel(Base):
    __tablename__ = "interfaces"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(32), unique=True, index=True, nullable=False)  # e.g., 'awg1', 'awg2'
    address = Column(String(64), nullable=False)                       # e.g., '10.12.0.1/16'
    listen_port = Column(Integer, nullable=False)                      # e.g., 51821
    public_key = Column(String(64), nullable=False)
    protocol_version = Column(String(32), default="v2.0")              # 'v2.0' or 'v3.1'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    users = relationship("UserModel", back_populates="interface", cascade="all, delete-orphan")

class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), index=True, nullable=False)
    interface_name = Column(String(32), ForeignKey("interfaces.name"), nullable=False)
    subnet = Column(String(64), nullable=False)                        # e.g., '10.12.1.0/24'
    subnet_index = Column(Integer, nullable=False)                     # e.g., 1
    telegram_id = Column(BigInteger, nullable=True)                    # Optional binding to TG
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    interface = relationship("InterfaceModel", back_populates="users")
    configs = relationship("ClientConfigModel", back_populates="user", cascade="all, delete-orphan")

class ClientConfigModel(Base):
    __tablename__ = "client_configs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    label = Column(String(64), nullable=False)                         # e.g., 'iPhone', 'MacBook'
    device_ip = Column(String(64), nullable=False)                     # e.g., '10.12.1.2'
    public_key = Column(String(64), nullable=False, unique=True)
    private_key = Column(String(64), nullable=False)
    preshared_key = Column(String(64), nullable=True)
    is_active = Column(Boolean, default=True)
    last_handshake = Column(DateTime, nullable=True)
    rx_bytes = Column(BigInteger, default=0)
    tx_bytes = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserModel", back_populates="configs")
