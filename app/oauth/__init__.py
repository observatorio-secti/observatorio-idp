from app.oauth.base import BaseOAuthProvider, OAuthUserInfo
from app.oauth.google import GoogleOAuthProvider
from app.oauth.orcid import OrcidOAuthProvider
from app.oauth.registry import get_oauth_provider

__all__ = [
    'BaseOAuthProvider',
    'GoogleOAuthProvider',
    'OAuthUserInfo',
    'OrcidOAuthProvider',
    'get_oauth_provider',
]
