from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings


class Base(DeclarativeBase):
    pass


connect_args = {}
engine_kwargs = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # In-memory SQLite databases belong to a single connection and vanish when it
    # closes. StaticPool keeps one connection so lifespan's create_all() and later
    # request sessions share the same schema.
    if settings.database_url == "sqlite://" or ":memory:" in settings.database_url:
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


# Columns added after the first public release. ``create_all`` creates new tables
# but never alters existing ones, so existing databases get these columns here.
# Every addition is nullable or has a default, which keeps the upgrade additive.
_ADDED_COLUMNS = {
    "alerts": {
        "rule_id": "INTEGER REFERENCES detection_rules(id)",
        "incident_id": "INTEGER REFERENCES incidents(id)",
    },
    "incidents": {"synthetic": "BOOLEAN NOT NULL DEFAULT {false}"},
}


def ensure_schema(bind=None) -> list[str]:
    """Add missing Milestone 5 columns to pre-existing tables. Returns the columns added."""
    bind = bind or engine
    inspector = inspect(bind)
    false_literal = "0" if bind.dialect.name == "sqlite" else "FALSE"
    added: list[str] = []
    with bind.begin() as connection:
        for table, columns in _ADDED_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    # Table/column names come from the constant above, never from user input.
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl.format(false=false_literal)}"))
                    added.append(f"{table}.{name}")
    return added
