"""Alembic environment configuration.

Configura Alembic para usar los modelos SQLAlchemy de ALERTA-LINK.
"""

import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Agregar backend al path para importar modelos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override URL from environment if available
database_url = os.getenv('DATABASE_URL')
if database_url:
    config.set_main_option('sqlalchemy.url', database_url)

# Importar modelos para autogeneracion de migraciones
try:
    from app.models import Base
    target_metadata = Base.metadata
except ImportError:
    # Fallback si no se pueden importar los modelos
    target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Genera SQL sin conectar a la base de datos.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Conecta a la base de datos y ejecuta las migraciones.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
