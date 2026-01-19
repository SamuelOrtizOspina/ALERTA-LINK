"""Add analysis_results table for storing analysis history

Revision ID: 002
Revises: 001
Create Date: 2026-01-08

Esta tabla almacena el historico de analisis de URLs, incluyendo:
- Scores (ML, heuristicas, total)
- Nivel de riesgo
- Senales detectadas
- Estado de APIs consultadas (Tranco, VirusTotal)
- Duracion y modo de analisis
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tabla analysis_results
    op.create_table(
        'analysis_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('url_normalized', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.Text(), nullable=True),

        # Resultados del analisis
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.Text(), nullable=False),
        sa.Column('signals', postgresql.JSONB(), nullable=True),

        # Scores individuales
        sa.Column('ml_score', sa.Integer(), nullable=True),
        sa.Column('heuristic_score', sa.Integer(), nullable=True),

        # Estado de APIs externas
        sa.Column('tranco_verified', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('tranco_rank', sa.Integer(), nullable=True),
        sa.Column('virustotal_checked', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('virustotal_detections', sa.Integer(), nullable=True),

        # Metadatos
        sa.Column('mode_used', sa.Text(), nullable=True, server_default='auto'),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('NOW()')),

        # Constraints
        sa.CheckConstraint('score >= 0 AND score <= 100', name='ck_analysis_score_range'),
        sa.CheckConstraint("risk_level IN ('LOW', 'MEDIUM', 'HIGH')",
                          name='ck_analysis_risk_level'),
        sa.CheckConstraint("mode_used IN ('online', 'offline', 'auto')",
                          name='ck_analysis_mode'),
    )

    # Indices para analysis_results
    op.create_index('idx_analysis_created_at', 'analysis_results', ['created_at'],
                    postgresql_using='btree', postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_analysis_score', 'analysis_results', ['score'])
    op.create_index('idx_analysis_risk_level', 'analysis_results', ['risk_level'])
    op.create_index('idx_analysis_url_hash', 'analysis_results', ['url_hash'])


def downgrade() -> None:
    op.drop_index('idx_analysis_url_hash', table_name='analysis_results')
    op.drop_index('idx_analysis_risk_level', table_name='analysis_results')
    op.drop_index('idx_analysis_score', table_name='analysis_results')
    op.drop_index('idx_analysis_created_at', table_name='analysis_results')
    op.drop_table('analysis_results')
