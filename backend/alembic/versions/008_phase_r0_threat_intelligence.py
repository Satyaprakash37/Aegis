"""Phase R0: Threat Intelligence Foundation - add in_kev, threat_level, exploit_refs.

Revision ID: 008
Revises: 007
Create Date: 2026-10-09 14:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '008'
down_revision: Union[str, None] = '007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add in_kev column with default false
    op.add_column(
        'vulnerabilities',
        sa.Column('in_kev', sa.Boolean(), server_default='false', nullable=False)
    )

    # 2. Add threat_level column
    op.add_column(
        'vulnerabilities',
        sa.Column('threat_level', sa.String(length=50), nullable=True)
    )

    # 3. Add exploit_refs JSONB column
    op.add_column(
        'vulnerabilities',
        sa.Column('exploit_refs', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )

    # 4. Create index on in_kev and threat_level for fast dashboard filtering
    op.create_index('ix_vulnerabilities_in_kev', 'vulnerabilities', ['in_kev'])
    op.create_index('ix_vulnerabilities_threat_level', 'vulnerabilities', ['threat_level'])


def downgrade() -> None:
    op.drop_index('ix_vulnerabilities_threat_level', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_in_kev', table_name='vulnerabilities')
    op.drop_column('vulnerabilities', 'exploit_refs')
    op.drop_column('vulnerabilities', 'threat_level')
    op.drop_column('vulnerabilities', 'in_kev')
