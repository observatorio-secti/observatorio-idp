from uuid import uuid4

import factory

from app.core.security import get_password_hash
from app.models.application import Application
from app.models.identity import Identity
from app.models.user import User


class UserFactory(factory.Factory):
    class Meta:
        model = User

    id = factory.LazyFunction(uuid4)
    email = factory.Sequence(lambda n: f'user_{n}@example.com')
    name = factory.Faker('name')
    password_hash = factory.LazyFunction(
        lambda: get_password_hash('testpassword123')
    )
    is_active = True


class ApplicationFactory(factory.Factory):
    class Meta:
        model = Application

    client_id = factory.Sequence(lambda n: f'client_{n}')
    client_secret = 'secret123'
    name = factory.Sequence(lambda n: f'Application {n}')
    redirect_uris = [
        'http://localhost:3000/auth/callback',
        'https://app.example.com/callback',
    ]
    is_active = True


class IdentityFactory(factory.Factory):
    class Meta:
        model = Identity

    id = factory.LazyFunction(uuid4)
    provider = 'google'
    provider_user_id = factory.Sequence(lambda n: f'google_sub_{n}')
    email = factory.Sequence(lambda n: f'user_{n}@gmail.com')
