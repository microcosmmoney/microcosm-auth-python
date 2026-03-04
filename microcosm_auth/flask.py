# microcosm_auth/flask.py
"""
Microcosm Auth SDK - Flask 适配器

用法:
    from flask import Flask, jsonify
    from microcosm_auth.flask import MicrocosmAuth

    app = Flask(__name__)
    auth = MicrocosmAuth(app, client_id='doublehelix')

    @app.route('/api/protected')
    @auth.require_auth
    def protected_route():
        user = auth.current_user
        return jsonify({'message': f'Hello {user.email}'})

    @app.route('/api/admin')
    @auth.require_role('admin')
    def admin_route():
        return jsonify({'message': 'Admin only'})
"""

from typing import Optional, Callable, Any
from functools import wraps

from flask import Flask, request, g, jsonify, Response

from .client import MicrocosmAuth as BaseMicrocosmAuth
from .models import User
from .exceptions import UnauthorizedError, InvalidTokenError, ForbiddenError


class MicrocosmAuth(BaseMicrocosmAuth):
    """
    Flask 专用认证客户端

    支持两种初始化方式:
        1. 构造函数传入 app: auth = MicrocosmAuth(app)
        2. 延迟初始化: auth = MicrocosmAuth(); auth.init_app(app)
    """

    def __init__(
        self,
        app: Optional[Flask] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        auth_endpoint: Optional[str] = None,
        **kwargs
    ):
        """
        初始化 Flask 认证客户端

        Args:
            app: Flask 应用实例（可选，延迟初始化时不传）
            client_id: OAuth Client ID
            client_secret: OAuth Client Secret
            auth_endpoint: 认证服务地址
            **kwargs: 其他参数
        """
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
        """
        Flask 工厂模式初始化

        用法:
            auth = MicrocosmAuth()

            def create_app():
                app = Flask(__name__)
                auth.init_app(app)
                return app
        """
        self.app = app

        # 从 Flask 配置读取
        if not self.client_id:
            self.client_id = app.config.get('MICROCOSM_CLIENT_ID')
        if not self.client_secret:
            self.client_secret = app.config.get('MICROCOSM_CLIENT_SECRET')
        if self.auth_endpoint == self.DEFAULT_AUTH_ENDPOINT:
            endpoint = app.config.get('MICROCOSM_AUTH_ENDPOINT')
            if endpoint:
                self.auth_endpoint = endpoint

        # 注册扩展
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['microcosm_auth'] = self

        # 请求后清理
        @app.teardown_appcontext
        def cleanup(exception=None):
            g.pop('microcosm_user', None)

    @property
    def current_user(self) -> Optional[User]:
        """获取当前请求的用户"""
        return getattr(g, 'microcosm_user', None)

    def require_auth(self, f: Callable) -> Callable:
        """
        装饰器: 要求登录

        用法:
            @app.route('/api/protected')
            @auth.require_auth
            def protected_route():
                user = auth.current_user
                return jsonify({'message': f'Hello {user.email}'})
        """
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
        """
        装饰器: 要求特定角色

        用法:
            @app.route('/api/admin')
            @auth.require_role('admin')
            def admin_route():
                return jsonify({'message': 'Admin only'})

            @app.route('/api/staff')
            @auth.require_role('admin', 'trader')
            def staff_route():
                return jsonify({'message': 'Staff only'})
        """
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
        """
        装饰器: 要求管理员权限

        用法:
            @app.route('/api/admin')
            @auth.require_admin
            def admin_route():
                return jsonify({'message': 'Admin only'})
        """
        return self.require_role('admin')(f)

    def optional_auth(self, f: Callable) -> Callable:
        """
        装饰器: 可选认证 (不强制登录)

        用法:
            @app.route('/api/public')
            @auth.optional_auth
            def public_route():
                user = auth.current_user
                if user:
                    return jsonify({'message': f'Hello {user.email}'})
                return jsonify({'message': 'Hello guest'})
        """
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
        """从请求中提取 token"""
        # Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]

        # Query parameter (某些场景)
        token = request.args.get('access_token')
        if token:
            return token

        # Cookie (如果配置了)
        token = request.cookies.get('mc_access_token')
        if token:
            return token

        return None

    def _unauthorized_response(self, message: str) -> tuple:
        """返回 401 响应"""
        return jsonify({
            'success': False,
            'data': None,
            'error': {
                'code': 'unauthorized',
                'message': message,
            }
        }), 401

    def _forbidden_response(self, message: str) -> tuple:
        """返回 403 响应"""
        return jsonify({
            'success': False,
            'data': None,
            'error': {
                'code': 'forbidden',
                'message': message,
            }
        }), 403


# 导出
__all__ = [
    'MicrocosmAuth',
    'User',
]
