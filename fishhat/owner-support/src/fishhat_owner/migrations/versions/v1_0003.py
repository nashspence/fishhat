"""Retain confirmed facts separately from uncertainty and preserve resolution roots."""

from alembic import op

revision = "v1_0003"
down_revision = "v1_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE request_effects(request_id TEXT PRIMARY KEY REFERENCES requests(request_id),known INTEGER,revision INTEGER NOT NULL,held INTEGER NOT NULL)"
    )
    # Only never-executed acceptance establishes a complete no-known-effect
    # history. Other imported rows cannot disprove facts lost by an older writer.
    # NULL preserves that uncertainty without inventing a confirmed effect.
    op.execute(
        "INSERT INTO request_effects SELECT request_id,CASE WHEN effect='known' THEN 1 WHEN state='accepted' AND effect='none' THEN 0 ELSE NULL END,0,CASE WHEN state='succeeded' THEN 0 ELSE 1 END FROM requests"
    )
    op.execute("CREATE INDEX request_effects_held ON request_effects(request_id) WHERE held=1")
    op.execute(
        "CREATE TABLE effect_resolutions(request_id TEXT NOT NULL REFERENCES requests(request_id),transition INTEGER NOT NULL,evidence_digest TEXT NOT NULL,PRIMARY KEY(request_id,transition))"
    )


def downgrade() -> None:
    raise RuntimeError("state migrations are forward-only")
