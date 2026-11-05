from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import settings


def int_to_base64url(val: int) -> str:
    """Converte um inteiro para representação Base64URL sem padding."""
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(val_bytes).rstrip(b'=').decode('ascii')


class KeyManager:
    """Gerencia par de chaves RSA (RS256) e exposição JWKS."""

    def __init__(self) -> None:
        self.kid = settings.IDP_KEY_ID

        if settings.IDP_PRIVATE_KEY_PEM.strip():
            raw_pem = (
                settings.IDP_PRIVATE_KEY_PEM.strip()
                .strip("\"'")
                .replace('\\n', '\n')
            )
            cleaned_pem = '\n'.join(
                line.strip() for line in raw_pem.splitlines() if line.strip()
            )
            self._private_key = serialization.load_pem_private_key(
                cleaned_pem.encode('utf-8'),
                password=None,
            )
        else:
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

        self._public_key = self._private_key.public_key()
        self._private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        self._public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

    @property
    def private_key_pem(self) -> str:
        return self._private_pem

    @property
    def public_key_pem(self) -> str:
        return self._public_pem

    def get_jwks(self) -> dict[str, Any]:
        """Gera o conjunto JWKS no formato padrão RFC 7517."""
        public_numbers = self._public_key.public_numbers()
        n = int_to_base64url(public_numbers.n)
        e = int_to_base64url(public_numbers.e)

        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'alg': 'RS256',
                    'kid': self.kid,
                    'n': n,
                    'e': e,
                }
            ]
        }

    def sign_jwt(self, claims: dict[str, Any]) -> str:
        """Assina claims JWT utilizando o par de chaves RSA (RS256) e o kid no cabeçalho."""
        headers = {'kid': self.kid, 'alg': 'RS256'}
        return jwt.encode(
            claims,
            self._private_pem,
            algorithm='RS256',
            headers=headers,
        )

    def decode_jwt(
        self,
        token: str,
        audience: str | None = None,
        verify_exp: bool = True,
    ) -> dict[str, Any]:
        """Decodifica e valida o JWT utilizando a chave pública RSA ativa."""
        options = {'verify_exp': verify_exp}
        decode_kwargs: dict[str, Any] = {
            'algorithms': ['RS256'],
            'options': options,
            'issuer': settings.IDP_ISSUER,
        }
        if audience:
            decode_kwargs['audience'] = audience
        else:
            options['verify_aud'] = False

        return jwt.decode(token, self._public_pem, **decode_kwargs)


key_manager = KeyManager()


def create_access_token(
    user_id: str,
    email: str,
    name: str,
    role: str = 'DEFAULT',
    client_id: str | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    """Emite um access token JWT padrão RS256 com claims especificados."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    claims: dict[str, Any] = {
        'iss': settings.IDP_ISSUER,
        'sub': str(user_id),
        'email': email,
        'name': name,
        'role': role,
        'iat': int(now.timestamp()),
        'exp': int(expire.timestamp()),
        'jti': str(uuid.uuid4()),
    }

    if client_id:
        claims['aud'] = client_id

    return key_manager.sign_jwt(claims)
