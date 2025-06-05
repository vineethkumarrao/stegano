"""
Database initialization and migration utilities.
"""

import os
import sys
from pathlib import Path
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command
import logging

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from models.base import Base, engine, DATABASE_URL
from config.settings import get_settings

logger = logging.getLogger(__name__)


def create_database_if_not_exists():
    """
    Create the database if it doesn't exist (PostgreSQL only).
    """
    settings = get_settings()
    
    if 'postgresql' not in DATABASE_URL:
        logger.info("Not using PostgreSQL, skipping database creation")
        return
        
    # Extract database name from URL
    db_name = DATABASE_URL.split('/')[-1]
    base_url = DATABASE_URL.rsplit('/', 1)[0]
    
    # Connect to postgres database to create our database
    admin_engine = create_engine(f"{base_url}/postgres")
    
    try:
        with admin_engine.connect() as conn:
            # Check if database exists
            result = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :db_name"),
                {"db_name": db_name}
            )
            
            if not result.fetchone():
                # Database doesn't exist, create it
                conn.execute(text(f"CREATE DATABASE {db_name}"))
                logger.info(f"Created database: {db_name}")
            else:
                logger.info(f"Database {db_name} already exists")
                
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        raise
    finally:
        admin_engine.dispose()


def init_alembic():
    """
    Initialize Alembic for database migrations.
    """
    alembic_dir = backend_dir / "alembic"
    
    if not alembic_dir.exists():
        logger.info("Initializing Alembic...")
        config = Config()
        config.set_main_option("script_location", str(alembic_dir))
        config.set_main_option("sqlalchemy.url", DATABASE_URL)
        
        command.init(config, str(alembic_dir))
        logger.info("Alembic initialized")
        
        # Update alembic.ini with our settings
        alembic_ini = backend_dir / "alembic.ini"
        if alembic_ini.exists():
            content = alembic_ini.read_text()
            content = content.replace(
                "sqlalchemy.url = driver://user:pass@localhost/dbname",
                f"sqlalchemy.url = {DATABASE_URL}"
            )
            alembic_ini.write_text(content)


def create_migration(message: str):
    """
    Create a new Alembic migration.
    """
    alembic_dir = backend_dir / "alembic"
    config = Config(str(backend_dir / "alembic.ini"))
    
    command.revision(config, autogenerate=True, message=message)
    logger.info(f"Created migration: {message}")


def run_migrations():
    """
    Run all pending Alembic migrations.
    """
    alembic_dir = backend_dir / "alembic"
    if not alembic_dir.exists():
        logger.warning("Alembic not initialized, creating tables directly")
        Base.metadata.create_all(bind=engine)
        return
        
    config = Config(str(backend_dir / "alembic.ini"))
    command.upgrade(config, "head")
    logger.info("Migrations completed")


def reset_database():
    """
    Reset the database by dropping and recreating all tables.
    WARNING: This will delete all data!
    """
    logger.warning("Resetting database - all data will be lost!")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    logger.info("Database reset completed")


def init_database():
    """
    Complete database initialization process.
    """
    try:
        logger.info("Starting database initialization...")
        
        # Step 1: Create database if needed
        create_database_if_not_exists()
        
        # Step 2: Initialize Alembic
        init_alembic()
        
        # Step 3: Run migrations or create tables
        run_migrations()
        
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management utilities")
    parser.add_argument("action", choices=[
        "init", "create-migration", "migrate", "reset"
    ], help="Action to perform")
    parser.add_argument("--message", "-m", help="Migration message")
    
    args = parser.parse_args()
    
    if args.action == "init":
        init_database()
    elif args.action == "create-migration":
        if not args.message:
            print("Error: --message required for creating migrations")
            sys.exit(1)
        create_migration(args.message)
    elif args.action == "migrate":
        run_migrations()
    elif args.action == "reset":
        confirm = input("This will delete all data. Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            reset_database()
        else:
            print("Database reset cancelled")
