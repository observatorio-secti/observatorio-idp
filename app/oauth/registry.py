from collections.abc import Callable

from app.core.config import Settings, settings
from app.oauth.base import BaseOAuthProvider
from app.oauth.google import GoogleOAuthProvider
from app.oauth.orcid import OrcidOAuthProvider


def get_oauth_provider(
    name: str, config: Settings | None = None
) -> BaseOAuthProvider:
    """Retorna a instância do provedor OAuth solicitado."""
    cfg = config or settings

    providers: dict[str, Callable[[], BaseOAuthProvider]] = {
        'google': lambda: GoogleOAuthProvider(cfg),
        'orcid': lambda: OrcidOAuthProvider(cfg),
    }

    factory = providers.get(name.lower())
    if not factory:
        supported = ', '.join(providers.keys())
        raise ValueError(
            f"Provedor OAuth '{name}' não suportado. Provedores válidos: {supported}"
        )

    return factory()
