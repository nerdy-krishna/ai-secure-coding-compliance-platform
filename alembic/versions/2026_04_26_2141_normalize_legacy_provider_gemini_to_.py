"""normalize_legacy_provider_gemini_to_google

Until 2026-04-27 the first-run setup form (`secure-code-ui/.../SetupPage.tsx`)
shipped a `<option value="gemini">` for Google's provider, which got
persisted verbatim into `llm_configurations.provider`. Run
`add-deepseek-grok-llm-support` tightened `LLMConfigurationBase.provider`
to a `Literal["openai","anthropic","google","deepseek","xai"]`, so any
pre-existing row with `provider='gemini'` now breaks `GET /llm-configs/`
on read-back validation. This migration normalises those rows.

The fix is a one-shot UPDATE — no schema change. Reversible: the
`downgrade()` revives the legacy spelling for any row this migration
touched, but rather than tracking per-row state we fall back to the
broad inverse (any row with `provider='google'` flips to `'gemini'`).
That inverse is acceptable for this case because (a) the Google
provider was previously *always* spelled `'gemini'` in the wild via
the setup form, and (b) the `LLMConfigurationRead.provider` field is
relaxed to `str` in the same change, so downgrades don't crash on
`'gemini'` either.

Revision ID: c0f39ef37367
Revises: 6b06a5036276
Create Date: 2026-04-26 21:41:58.926429

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c0f39ef37367"
down_revision: Union[str, None] = "6b06a5036276"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE llm_configurations SET provider = 'google' "
            "WHERE provider = 'gemini'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE llm_configurations SET provider = 'gemini' "
            "WHERE provider = 'google'"
        )
    )
