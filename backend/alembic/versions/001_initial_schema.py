"""Initial database schema with 5 core tables, enums, and indexes.

Revision ID: 001
Revises: 
Create Date: 2026-10-06 04:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create Users Table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column(
            'role',
            sa.Enum('admin', 'analyst', 'viewer', name='user_role_enum'),
            nullable=False,
        ),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # 2. Create Assets Table
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=True),
        sa.Column(
            'asset_type',
            sa.Enum('server', 'web', 'db', 'network', name='asset_type_enum'),
            nullable=False,
        ),
        sa.Column(
            'environment',
            sa.Enum('production', 'staging', 'dev', name='asset_environment_enum'),
            nullable=False,
        ),
        sa.Column('criticality', sa.Integer(), nullable=False),
        sa.Column('owner', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_assets_ip_address'), 'assets', ['ip_address'], unique=True)

    # 3. Create Scans Table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column(
            'scan_type',
            sa.Enum('quick', 'full', name='scan_type_enum'),
            nullable=False,
        ),
        sa.Column(
            'status',
            sa.Enum('pending', 'running', 'completed', 'failed', name='scan_status_enum'),
            nullable=False,
            server_default='pending',
        ),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_vulns_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('raw_output', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scans_asset_id'), 'scans', ['asset_id'], unique=False)

    # 4. Create Vulnerabilities Table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=False),
        sa.Column(
            'severity',
            sa.Enum('critical', 'high', 'medium', 'low', 'none', name='vulnerability_severity_enum'),
            nullable=False,
        ),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('service', sa.String(length=100), nullable=True),
        sa.Column('service_version', sa.String(length=100), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column(
            'status',
            sa.Enum('open', 'in_progress', 'mitigated', 'false_positive', name='vulnerability_status_enum'),
            nullable=False,
            server_default='open',
        ),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_vulnerabilities_cve_id'), 'vulnerabilities', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_severity'), 'vulnerabilities', ['severity'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_status'), 'vulnerabilities', ['status'], unique=False)

    # 5. Create Reports Table
    op.create_table(
        'reports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            'report_type',
            sa.Enum('executive', 'detailed', 'compliance', name='report_type_enum'),
            nullable=False,
        ),
        sa.Column(
            'format',
            sa.Enum('pdf', 'excel', name='report_format_enum'),
            nullable=False,
        ),
        sa.Column('generated_by', sa.Integer(), nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['generated_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_reports_generated_by'), 'reports', ['generated_by'], unique=False)


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.drop_index(op.f('ix_reports_generated_by'), table_name='reports')
    op.drop_table('reports')

    op.drop_index(op.f('ix_vulnerabilities_status'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_severity'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_cve_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')

    op.drop_index(op.f('ix_scans_asset_id'), table_name='scans')
    op.drop_table('scans')

    op.drop_index(op.f('ix_assets_ip_address'), table_name='assets')
    op.drop_table('assets')

    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

    # Drop custom enums
    sa.Enum(name='report_format_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='report_type_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='vulnerability_status_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='vulnerability_severity_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='scan_status_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='scan_type_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='asset_environment_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='asset_type_enum').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='user_role_enum').drop(op.get_bind(), checkfirst=True)
