"""Add a server-managed account role for authorization policies.

Revision ID: 0003_account_roles
Revises: 0002_auth_cv
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_account_roles"
down_revision = "0002_auth_cv"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("role", sa.String(length=32), server_default="candidate", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("users", "role")
