# Developed by AI Agent

from typing import Optional, Tuple

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .client import MicrocosmAuth, init_auth as _init_auth, get_auth
from .models import User
from .exceptions import ConfigurationError

security = HTTPBearer(auto_error=False)

_auth_instance: Optional[MicrocosmAuth] = None


def init_auth(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    **kwargs
) -> MicrocosmAuth:
    global _auth_instance
    _auth_instance = MicrocosmAuth(
        client_id=client_id,
        client_secret=client_secret,
        auth_endpoint=auth_endpoint,
        **kwargs
    )
    _init_auth(client_id, client_secret, auth_endpoint, **kwargs)
    return _auth_instance


def get_auth_instance() -> MicrocosmAuth:
    if _auth_instance is None:
        try:
            return get_auth()
        except ConfigurationError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='MicrocosmAuth not initialized. Call init_auth() first.',
            )
    return _auth_instance


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Missing authorization header',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    auth = get_auth_instance()
    user = auth.verify_token(credentials.credentials)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid or expired token',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[User]:
    if not credentials:
        return None

    auth = get_auth_instance()
    return auth.verify_token(credentials.credentials)


def require_role(*roles: str):
    async def check_role(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f'Insufficient permissions. Required role: {", ".join(roles)}',
            )
        return user

    return check_role


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Admin access required',
        )
    return user


async def get_user_and_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Tuple[User, str]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Missing authorization header',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    auth = get_auth_instance()
    user = auth.verify_token(credentials.credentials)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid or expired token',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    return user, credentials.credentials


CurrentUser = Depends(get_current_user)
OptionalUser = Depends(get_optional_user)
AdminUser = Depends(require_admin)

__all__ = [
    'init_auth',
    'get_auth_instance',
    'get_current_user',
    'get_optional_user',
    'require_role',
    'require_admin',
    'get_user_and_token',
    'User',
    'CurrentUser',
    'OptionalUser',
    'AdminUser',
]
