import hashlib
import secrets

from pwdlib import PasswordHash

# Utiliza Argon2id com parâmetros recomendados para segurança moderna
pwd_context = PasswordHash.recommended()


def get_password_hash(password: str) -> str:
    """Gera hash seguro da senha com Argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str | None) -> bool:
    """Verifica se a senha em texto plano coincide com o hash Argon2."""
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def hash_token(token: str) -> str:
    """Gera o hash SHA-256 de tokens sensíveis (refresh tokens, authorization codes)."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Gera um token criptograficamente seguro e URL-safe."""
    return secrets.token_urlsafe(nbytes)
