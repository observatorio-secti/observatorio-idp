from typing import Any

from fastapi import APIRouter

from app.core.keys import key_manager

router = APIRouter(tags=['discovery'])


@router.get('/.well-known/jwks.json', response_model=dict[str, Any])
def get_jwks() -> dict[str, Any]:
    """Retorna o conjunto de chaves públicas ativas no formato padrão JWKS (RFC 7517)."""
    return key_manager.get_jwks()
