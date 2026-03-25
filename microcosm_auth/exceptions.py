# Developed by AI Agent

from typing import Optional


class MicrocosmAuthError(Exception):

    def __init__(self, message: str, code: str = "auth_error", status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code

    def to_dict(self):
        return {
            'success': False,
            'data': None,
            'error': {
                'code': self.code,
                'message': self.message,
            }
        }


class UnauthorizedError(MicrocosmAuthError):

    def __init__(self, message: str = "Unauthorized", code: str = "unauthorized"):
        super().__init__(message, code, 401)


class InvalidTokenError(MicrocosmAuthError):

    def __init__(self, message: str = "Invalid or expired token"):
        super().__init__(message, "invalid_token", 401)


class TokenExpiredError(MicrocosmAuthError):

    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, "token_expired", 401)


class ForbiddenError(MicrocosmAuthError):

    def __init__(self, message: str = "Insufficient permissions", code: str = "forbidden"):
        super().__init__(message, code, 403)


class ConfigurationError(MicrocosmAuthError):

    def __init__(self, message: str = "MicrocosmAuth not configured"):
        super().__init__(message, "configuration_error", 500)


class IntrospectError(MicrocosmAuthError):

    def __init__(self, message: str = "Token introspection failed"):
        super().__init__(message, "introspect_error", 500)
