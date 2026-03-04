# microcosm_auth/__init__.py
"""
Microcosm Auth SDK for Python

一个简单、安全的 Python 认证库，让任何项目通过几行代码接入 Microcosm 认证系统。

基础用法 (Flask):
    from flask import Flask
    from microcosm_auth import MicrocosmAuth

    app = Flask(__name__)
    auth = MicrocosmAuth(client_id='your_client_id')

    @app.route('/api/protected')
    @auth.require_auth
    def protected():
        user = auth.current_user
        return {'message': f'Hello {user.email}'}

基础用法 (FastAPI):
    from fastapi import FastAPI, Depends
    from microcosm_auth.fastapi import init_auth, get_current_user, User

    app = FastAPI()
    init_auth(client_id='your_client_id')

    @app.get('/api/protected')
    async def protected(user: User = Depends(get_current_user)):
        return {'message': f'Hello {user.email}'}

环境变量:
    MICROCOSM_CLIENT_ID: OAuth Client ID
    MICROCOSM_CLIENT_SECRET: OAuth Client Secret (仅后端需要)
    MICROCOSM_AUTH_ENDPOINT: 认证服务地址 (默认 https://microcosm.money)
"""

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

# 便捷别名
require_auth = lambda auth: auth.require_auth
require_role = lambda auth, *roles: auth.require_role(*roles)

__all__ = [
    # 版本
    '__version__',

    # 核心类
    'MicrocosmAuth',
    'User',
    'TokenInfo',

    # 全局实例
    'init_auth',
    'get_auth',

    # 异常
    'MicrocosmAuthError',
    'UnauthorizedError',
    'InvalidTokenError',
    'TokenExpiredError',
    'ForbiddenError',
    'ConfigurationError',
    'IntrospectError',
]
