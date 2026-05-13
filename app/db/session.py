"""
Database connection and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import get_settings

settings = get_settings()

# Create SQLAlchemy engine
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    echo=False
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class for models
Base = declarative_base()


def get_db():
    """
    Dependency for getting database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database tables
    """
    # Import all models so their tables are registered before create_all
    import app.models.models  # noqa: F401
    import app.models.compliance  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Seed compliance frameworks and controls
    from app.services.compliance_service import compliance_service
    db = SessionLocal()
    try:
        compliance_service.seed_frameworks(db)
    finally:
        db.close()
