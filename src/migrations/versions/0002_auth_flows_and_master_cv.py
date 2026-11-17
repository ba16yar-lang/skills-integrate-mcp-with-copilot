"""Add verified email, OAuth identities, auth challenges, and Master CV.

Revision ID: 0002_auth_cv
Revises: 0001_accounts
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_auth_cv"
down_revision = "0001_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.alter_column("email", existing_type=sa.String(length=320), nullable=True)
        batch.alter_column("password_hash", existing_type=sa.String(length=256), nullable=True)
        batch.add_column(sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("email_verified_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("credential_version", sa.Integer(), nullable=False, server_default="0"))

    op.create_table(
        "auth_challenges",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index("ix_auth_challenges_user_id", "auth_challenges", ["user_id"])
    op.create_index("ix_auth_challenges_expires_at", "auth_challenges", ["expires_at"])
    op.create_table(
        "oauth_identities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_oauth_issuer_subject"),
    )
    op.create_index("ix_oauth_identities_user_id", "oauth_identities", ["user_id"])
    op.create_table(
        "master_cvs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_master_cvs_user_id", "master_cvs", ["user_id"], unique=True)
    op.create_table(
        "master_cv_revisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("master_cv_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["master_cv_id"], ["master_cvs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("master_cv_id", "version", name="uq_master_cv_revision_version"),
    )
    op.create_index("ix_master_cv_revisions_master_cv_id", "master_cv_revisions", ["master_cv_id"])


def downgrade() -> None:
    users_with_external_only_login = op.get_bind().execute(
        sa.text("SELECT id FROM users WHERE email IS NULL OR password_hash IS NULL LIMIT 1")
    ).first()
    if users_with_external_only_login:
        raise RuntimeError("Cannot downgrade while external-identity-only accounts exist")
    op.drop_index("ix_master_cv_revisions_master_cv_id", table_name="master_cv_revisions")
    op.drop_table("master_cv_revisions")
    op.drop_index("ix_master_cvs_user_id", table_name="master_cvs")
    op.drop_table("master_cvs")
    op.drop_index("ix_oauth_identities_user_id", table_name="oauth_identities")
    op.drop_table("oauth_identities")
    op.drop_index("ix_auth_challenges_expires_at", table_name="auth_challenges")
    op.drop_index("ix_auth_challenges_user_id", table_name="auth_challenges")
    op.drop_table("auth_challenges")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("credential_version")
        batch.drop_column("email_verified_at")
        batch.drop_column("email_verified")
        batch.alter_column("email", existing_type=sa.String(length=320), nullable=False)
        batch.alter_column("password_hash", existing_type=sa.String(length=256), nullable=False)
