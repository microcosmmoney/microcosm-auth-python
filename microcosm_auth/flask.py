# Developed by AI Agent

from typing import Optional, Callable, Any
from functools import wraps

from flask import Flask, request, g, jsonify, Response

from .client import MicrocosmAuth as BaseMicrocosmAuth
from .models import User
from .exceptions import UnauthorizedError, InvalidTokenError, ForbiddenError


class MicrocosmAuth(BaseMicrocosmAuth):

    def __init__(
        self,
        app: Optional[Flask] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        auth_endpoint: Optional[str] = None,
        **kwargs
    ):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            auth_endpoint=auth_endpoint,
            **kwargs
        )
        self.app = app

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        self.app = app

        if not self.client_id:
            self.client_id = app.config.get('MICROCOSM_CLIENT_ID')
        if not self.client_secret:
            self.client_secret = app.config.get('MICROCOSM_CLIENT_SECRET')
        if self.auth_endpoint == self.DEFAULT_AUTH_ENDPOINT:
            endpoint = app.config.get('MICROCOSM_AUTH_ENDPOINT')
            if endpoint:
                self.auth_endpoint = endpoint

        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['microcosm_auth'] = self

        @app.teardown_appcontext
        def cleanup(exception=None):
            g.pop('microcosm_user', None)

    @property
    def current_user(self) -> Optional[User]:
        return getattr(g, 'microcosm_user', None)

    def require_auth(self, f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs) -> Any:
            token = self._extract_token()
            if not token:
                return self._unauthorized_response('Missing authorization header')

            user = self.verify_token(token)
            if not user:
                return self._unauthorized_response('Invalid or expired token')

            g.microcosm_user = user
            return f(*args, **kwargs)

        return decorated

    def require_role(self, *roles: str) -> Callable:
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            @self.require_auth
            def decorated(*args, **kwargs) -> Any:
                user = self.current_user
                if user is None or user.role not in roles:
                    return self._forbidden_response(
                        f'Insufficient permissions. Required role: {", ".join(roles)}'
                    )
                return f(*args, **kwargs)

            return decorated
        return decorator

    def require_admin(self, f: Callable) -> Callable:
        return self.require_role('admin')(f)

    def optional_auth(self, f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs) -> Any:
            token = self._extract_token()
            if token:
                user = self.verify_token(token)
                if user:
                    g.microcosm_user = user
            return f(*args, **kwargs)

        return decorated

    def _extract_token(self) -> Optional[str]:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]

        token = request.args.get('access_token')
        if token:
            return token

        token = request.cookies.get('mc_access_token')
        if token:
            return token

        return None

    def _unauthorized_response(self, message: str) -> tuple:
        return jsonify({
            'success': False,
            'data': None,
            'error': {
                'code': 'unauthorized',
                'message': message,
            }
        }), 401

    def _forbidden_response(self, message: str) -> tuple:
        return jsonify({
            'success': False,
            'data': None,
            'error': {
                'code': 'forbidden',
                'message': message,
            }
        }), 403


__all__ = [
    'MicrocosmAuth',
    'User',
]
