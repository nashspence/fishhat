"""Index only unresolved holds; preserve all accepted replay identities."""

from alembic import op

revision = "v1_0002"
down_revision = "v1_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX requests_active ON requests(request_id) WHERE state IN ('accepted','running','waiting','quarantined') OR (state IN ('failed','cancelled') AND effect != 'none')"
    )


def downgrade() -> None:
    raise RuntimeError("state migrations are forward-only")
