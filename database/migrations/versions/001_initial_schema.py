"""Initial schema - ingested_urls and reports tables

Revision ID: 001
Revises:
Create Date: 2026-01-01

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tabla ingested_urls
    op.create_table(
        'ingested_urls',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('url_normalized', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.Text(), nullable=True),
        sa.Column('label', sa.Integer(), nullable=True),
        sa.Column('source', sa.Text(), nullable=True, server_default='manual'),
        sa.Column('raw_payload', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.CheckConstraint('label IS NULL OR label IN (0, 1)', name='ck_ingested_label'),
    )

    # Indices para ingested_urls
    op.create_index('idx_ingested_created_at', 'ingested_urls', ['created_at'],
                    postgresql_using='btree', postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_ingested_label', 'ingested_urls', ['label'])
    op.create_index('idx_ingested_url_hash', 'ingested_urls', ['url_hash'])

    # Tabla reports
    op.create_table(
        'reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('url_normalized', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.Text(), nullable=True),
        sa.Column('label', sa.Text(), nullable=False),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('contact', sa.Text(), nullable=True),
        sa.Column('source', sa.Text(), nullable=True, server_default='mobile_app'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.CheckConstraint("label IN ('phishing', 'malware', 'scam', 'unknown')",
                          name='ck_reports_label'),
    )

    # Indices para reports
    op.create_index('idx_reports_created_at', 'reports', ['created_at'],
                    postgresql_using='btree', postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_reports_label', 'reports', ['label'])
    op.create_index('idx_reports_url_hash', 'reports', ['url_hash'])


def downgrade() -> None:
    op.drop_index('idx_reports_url_hash', table_name='reports')
    op.drop_index('idx_reports_label', table_name='reports')
    op.drop_index('idx_reports_created_at', table_name='reports')
    op.drop_table('reports')

    op.drop_index('idx_ingested_url_hash', table_name='ingested_urls')
    op.drop_index('idx_ingested_label', table_name='ingested_urls')
    op.drop_index('idx_ingested_created_at', table_name='ingested_urls')
    op.drop_table('ingested_urls')
