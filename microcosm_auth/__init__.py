# Developed by AI Agent

__version__ = '0.1.0'
__author__ = 'Microcosm Team'

from .models import User, TokenInfo
from .client import MicrocosmAuth, init_auth, get_auth
from .exceptions import (
    MicrocosmAuthError,
    UnauthorizedError,
    InvalidTokenError,
    TokenExpiredError,
    ForbiddenError,
    ConfigurationError,
    IntrospectError,
)

require_auth = lambda auth: auth.require_auth
require_role = lambda auth, *roles: auth.require_role(*roles)

__all__ = [
    '__version__',
    'MicrocosmAuth',
    'User',
    'TokenInfo',
    'init_auth',
    'get_auth',
    'MicrocosmAuthError',
    'UnauthorizedError',
    'InvalidTokenError',
    'TokenExpiredError',
    'ForbiddenError',
    'ConfigurationError',
    'IntrospectError',
]
