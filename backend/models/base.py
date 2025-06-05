"""
Base database configuration for SQLAlchemy models.
"""

from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
from typing import Generator

# Database configuration
DATABASE_URL = os.getenv(
    'DATABASE_URL', 
    'sqlite:///./stegano_scanner.db'
)

# SQLAlchemy engine configuration
engine = create_engine(
    DATABASE_URL,
    echo=os.getenv('SQL_DEBUG', 'false').lower() == 'true',
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={
        "check_same_thread": False
    } if 'sqlite' in DATABASE_URL else {
        "options": "-c timezone=utc"
    } if 'postgresql' in DATABASE_URL else {}
)

# Session configuration
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base model class
Base = declarative_base()

# Metadata configuration for migrations
metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

Base.metadata = metadata


def get_db() -> Generator:
    """
    Dependency function to get database session.
    Used with FastAPI dependency injection.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)


def drop_tables():
    """Drop all database tables."""
    Base.metadata.drop_all(bind=engine)


def reset_database():
    """Reset database by dropping and recreating all tables."""
    drop_tables()
    create_tables()
