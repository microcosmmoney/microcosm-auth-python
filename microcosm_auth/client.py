# Developed by AI Agent

import os
import time
import logging
from typing import Optional, Dict, Any, Callable
from functools import wraps

import requests

from .models import User, TokenInfo
from .exceptions import (
    MicrocosmAuthError,
    UnauthorizedError,
    InvalidTokenError,
    ForbiddenError,
    ConfigurationError,
    IntrospectError,
)

logger = logging.getLogger(__name__)


class MicrocosmAuth:

    DEFAULT_AUTH_ENDPOINT = 'https://microcosm.money'
    DEFAULT_CACHE_TTL = 60

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        auth_endpoint: Optional[str] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        debug: bool = False,
    ):
        self.client_id = client_id or os.environ.get('MICROCOSM_CLIENT_ID')
        self.client_secret = client_secret or os.environ.get('MICROCOSM_CLIENT_SECRET')
        self.auth_endpoint = auth_endpoint or os.environ.get(
            'MICROCOSM_AUTH_ENDPOINT', self.DEFAULT_AUTH_ENDPOINT
        )
        self.cache_ttl = cache_ttl
        self.debug = debug

        self._cache: Dict[str, Dict[str, Any]] = {}

        self._current_user: Optional[User] = None

        if not self.client_id:
            logger.warning(
                'MicrocosmAuth: client_id not provided. '
                'Set MICROCOSM_CLIENT_ID environment variable or pass client_id parameter.'
            )

        self._log(f'Initialized with endpoint: {self.auth_endpoint}')

    @property
    def current_user(self) -> Optional[User]:
        try:
            from flask import g
            return getattr(g, 'microcosm_user', None)
        except (ImportError, RuntimeError):
            pass

        return self._current_user

    def verify_token(self, token: str) -> Optional[User]:
        if not token:
            self._log('verify_token: empty token')
            return None

        cached = self._cache.get(token)
        if cached and cached['expires'] > time.time():
            self._log(f"verify_token: cache hit for token ...{token[-8:]}")
            return cached['user']

        try:
            token_info = self._introspect(token)
            if not token_info.active:
                self._log(f"verify_token: token inactive ...{token[-8:]}")
                return None

            user = token_info.user
            if user:
                self._cache[token] = {
                    'user': user,
                    'expires': time.time() + self.cache_ttl,
                }
                self._log(f"verify_token: success, user={user.uid}")

            return user

        except Exception as e:
            logger.error(f'[MicrocosmAuth] Token verification failed: {e}')
            return None

    def introspect_token(self, token: str) -> TokenInfo:
        return self._introspect(token)

    def require_auth(self, f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            from flask import request, jsonify, g

            token = self._extract_token_from_flask()
            if not token:
                return jsonify(UnauthorizedError('Missing authorization header').to_dict()), 401

            user = self.verify_token(token)
            if not user:
                return jsonify(InvalidTokenError().to_dict()), 401

            g.microcosm_user = user
            return f(*args, **kwargs)

        return decorated

    def require_role(self, *roles: str) -> Callable:
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            @self.require_auth
            def decorated(*args, **kwargs):
                from flask import jsonify

                user = self.current_user
                if user is None or user.role not in roles:
                    return jsonify(ForbiddenError().to_dict()), 403
                return f(*args, **kwargs)

            return decorated
        return decorator

    def clear_cache(self, token: Optional[str] = None):
        if token:
            self._cache.pop(token, None)
        else:
            self._cache.clear()
        self._log(f'Cache cleared: {"all" if token is None else f"...{token[-8:]}"}')

    def _introspect(self, token: str) -> TokenInfo:
        url = f'{self.auth_endpoint}/oauth/introspect'

        try:
            response = requests.post(
                url,
                json={'token': token},
                headers={'Content-Type': 'application/json'},
                timeout=5,
            )

            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                logger.error(f'[MicrocosmAuth] Non-JSON response from introspect: {response.text[:200]}')
                raise IntrospectError(f'Invalid response format: {content_type}')

            data = response.json()

            if not response.ok:
                error_msg = data.get('error', {}).get('message', 'Unknown error')
                raise IntrospectError(error_msg)

            if 'data' in data and isinstance(data['data'], dict):
                token_data = data['data']
            else:
                token_data = data

            return TokenInfo.from_introspect(token_data)

        except requests.RequestException as e:
            logger.error(f'[MicrocosmAuth] Introspect request failed: {e}')
            raise IntrospectError(str(e))

    def _extract_token_from_flask(self) -> Optional[str]:
        from flask import request

        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]

        token = request.args.get('access_token')
        if token:
            return token

        return None

    def _log(self, message: str):
        if self.debug:
            logger.info(f'[MicrocosmAuth] {message}')


_default_auth: Optional[MicrocosmAuth] = None


def init_auth(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    **kwargs
) -> MicrocosmAuth:
    global _default_auth
    _default_auth = MicrocosmAuth(
        client_id=client_id,
        client_secret=client_secret,
        auth_endpoint=auth_endpoint,
        **kwargs
    )
    return _default_auth


def get_auth() -> MicrocosmAuth:
    if _default_auth is None:
        raise ConfigurationError('MicrocosmAuth not initialized. Call init_auth() first.')
    return _default_auth
