# microcosm_auth/client.py
"""
Microcosm Auth SDK - Core Client

注意：所有认证必须通过 Microcosm Auth SDK，禁止直连 Firebase
"""

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
    """
    Microcosm 认证客户端

    用法:
        auth = MicrocosmAuth(client_id='doublehelix')

        # Flask 装饰器
        @auth.require_auth
        def protected_route():
            user = auth.current_user
            return {'message': f'Hello {user.email}'}

        # 手动验证
        user = auth.verify_token(token)
    """

    # 默认配置
    DEFAULT_AUTH_ENDPOINT = 'https://microcosm.money'
    DEFAULT_CACHE_TTL = 60  # 缓存 60 秒

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        auth_endpoint: Optional[str] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL,
        debug: bool = False,
    ):
        """
        初始化认证客户端

        Args:
            client_id: OAuth Client ID (可从环境变量 MICROCOSM_CLIENT_ID 读取)
            client_secret: OAuth Client Secret (可从环境变量 MICROCOSM_CLIENT_SECRET 读取)
            auth_endpoint: Microcosm 认证服务地址
            cache_ttl: Token 验证结果缓存时间（秒）
            debug: 是否开启调试日志
        """
        self.client_id = client_id or os.environ.get('MICROCOSM_CLIENT_ID')
        self.client_secret = client_secret or os.environ.get('MICROCOSM_CLIENT_SECRET')
        self.auth_endpoint = auth_endpoint or os.environ.get(
            'MICROCOSM_AUTH_ENDPOINT', self.DEFAULT_AUTH_ENDPOINT
        )
        self.cache_ttl = cache_ttl
        self.debug = debug

        # 内存缓存（生产环境建议使用 Redis）
        self._cache: Dict[str, Dict[str, Any]] = {}

        # 当前请求的用户（Flask/WSGI 线程本地存储）
        self._current_user: Optional[User] = None

        if not self.client_id:
            logger.warning(
                'MicrocosmAuth: client_id not provided. '
                'Set MICROCOSM_CLIENT_ID environment variable or pass client_id parameter.'
            )

        self._log(f'Initialized with endpoint: {self.auth_endpoint}')

    @property
    def current_user(self) -> Optional[User]:
        """获取当前请求的用户（需要先调用 require_auth 装饰器）"""
        # Flask: 从 g 对象获取
        try:
            from flask import g
            return getattr(g, 'microcosm_user', None)
        except (ImportError, RuntimeError):
            pass

        # 回退到实例变量
        return self._current_user

    def verify_token(self, token: str) -> Optional[User]:
        """
        验证 Access Token

        Args:
            token: Bearer token 字符串

        Returns:
            User 对象（如果有效），否则 None
        """
        if not token:
            self._log('verify_token: empty token')
            return None

        # 检查缓存
        cached = self._cache.get(token)
        if cached and cached['expires'] > time.time():
            self._log(f"verify_token: cache hit for token ...{token[-8:]}")
            return cached['user']

        # 调用 introspect API
        try:
            token_info = self._introspect(token)
            if not token_info.active:
                self._log(f"verify_token: token inactive ...{token[-8:]}")
                return None

            user = token_info.user
            if user:
                # 缓存结果
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
        """
        调用 introspect API 获取 Token 详细信息

        Args:
            token: Bearer token 字符串

        Returns:
            TokenInfo 对象

        Raises:
            IntrospectError: API 调用失败
        """
        return self._introspect(token)

    def require_auth(self, f: Callable) -> Callable:
        """
        Flask 装饰器: 要求登录

        用法:
            @app.route('/api/protected')
            @auth.require_auth
            def protected_route():
                user = auth.current_user
                return {'message': f'Hello {user.email}'}
        """
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
        """
        Flask 装饰器: 要求特定角色

        用法:
            @app.route('/api/admin')
            @auth.require_role('admin')
            def admin_route():
                return {'message': 'Admin only'}
        """
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
        """
        清除缓存

        Args:
            token: 指定 token 的缓存，None 则清除所有
        """
        if token:
            self._cache.pop(token, None)
        else:
            self._cache.clear()
        self._log(f'Cache cleared: {"all" if token is None else f"...{token[-8:]}"}')

    def _introspect(self, token: str) -> TokenInfo:
        """调用 Microcosm introspect API"""
        url = f'{self.auth_endpoint}/oauth/introspect'

        try:
            response = requests.post(
                url,
                json={'token': token},
                headers={'Content-Type': 'application/json'},
                timeout=5,
            )

            # 安全解析响应
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                logger.error(f'[MicrocosmAuth] Non-JSON response from introspect: {response.text[:200]}')
                raise IntrospectError(f'Invalid response format: {content_type}')

            data = response.json()

            if not response.ok:
                error_msg = data.get('error', {}).get('message', 'Unknown error')
                raise IntrospectError(error_msg)

            # 兼容两种响应格式
            # 1. {success: true, data: {...}}
            # 2. {active: true, uid: ...}
            if 'data' in data and isinstance(data['data'], dict):
                token_data = data['data']
            else:
                token_data = data

            return TokenInfo.from_introspect(token_data)

        except requests.RequestException as e:
            logger.error(f'[MicrocosmAuth] Introspect request failed: {e}')
            raise IntrospectError(str(e))

    def _extract_token_from_flask(self) -> Optional[str]:
        """从 Flask 请求中提取 token"""
        from flask import request

        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]

        # 也检查查询参数（某些场景下使用）
        token = request.args.get('access_token')
        if token:
            return token

        return None

    def _log(self, message: str):
        """调试日志"""
        if self.debug:
            logger.info(f'[MicrocosmAuth] {message}')


# 全局实例（可选）
_default_auth: Optional[MicrocosmAuth] = None


def init_auth(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    **kwargs
) -> MicrocosmAuth:
    """
    初始化全局认证实例

    Args:
        client_id: OAuth Client ID
        client_secret: OAuth Client Secret
        auth_endpoint: 认证服务地址
        **kwargs: 其他参数传递给 MicrocosmAuth

    Returns:
        MicrocosmAuth 实例
    """
    global _default_auth
    _default_auth = MicrocosmAuth(
        client_id=client_id,
        client_secret=client_secret,
        auth_endpoint=auth_endpoint,
        **kwargs
    )
    return _default_auth


def get_auth() -> MicrocosmAuth:
    """获取全局认证实例"""
    if _default_auth is None:
        raise ConfigurationError('MicrocosmAuth not initialized. Call init_auth() first.')
    return _default_auth
