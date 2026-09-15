"""Alembic environment.

Two things are wired up here that the generated template leaves blank:

1. The connection URL comes from .env via app.config, NOT from alembic.ini.
   alembic.ini is committed to git; the URL contains a password, so it must
   never be written there.
2. target_metadata points at our Base, which is what lets
   `alembic revision --autogenerate` diff the models against the live DB.
"""
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from app.config import get_settings
from app.models import Base

config = context.config

# Inject the real URL at runtime, overriding the empty one in alembic.ini.
# Skipped when a caller already set one -- the test suite points Alembic at a
# separate test database this way. "%" is doubled because alembic.ini is read
# by configparser, which treats a lone "%" (common in URL-encoded passwords)
# as interpolation syntax.
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", get_settings().database_url.replace("%", "%%"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (`alembic upgrade head --sql`)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect to the database and apply migrations."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Without this, autogenerate ignores column type changes.
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
