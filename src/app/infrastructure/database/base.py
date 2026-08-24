"""SQLAlchemy metadata without runtime service configuration side effects."""

from sqlalchemy.orm import declarative_base


Base = declarative_base()
