from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = {}
engine_kwargs = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # :memory: databases vanish when a connection closes. StaticPool keeps one
    # connection so lifespan's create_all() and later sessions share tables.
    if ":memory:" in settings.database_url:
        engine_kwargs["poolclass"] = StaticPool
        # pool_pre_ping issues a checkout query that is unnecessary (and can
        # confuse) a single shared in-memory connection.
        engine_kwargs["pool_pre_ping"] = False
engine = create_engine(settings.database_url, connect_args=connect_args, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
