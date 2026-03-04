# microcosm_auth/fastapi.py
"""
Microcosm Auth SDK - FastAPI 适配器

用法:
    from fastapi import FastAPI, Depends
    from microcosm_auth.fastapi import init_auth, get_current_user, require_role, User

    app = FastAPI()
    init_auth(client_id='doublehelix')

    @app.get('/api/protected')
    async def protected_route(user: User = Depends(get_current_user)):
        return {'message': f'Hello {user.email}'}

    @app.get('/api/admin')
    async def admin_route(user: User = Depends(require_role('admin'))):
        return {'message': 'Admin only'}
"""

from typing import Optional, Tuple

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from .client import MicrocosmAuth, init_auth as _init_auth, get_auth
from .models import User
from .exceptions import ConfigurationError

# FastAPI 安全依赖
security = HTTPBearer(auto_error=False)

# 模块级别的 auth 实例
_auth_instance: Optional[MicrocosmAuth] = None


def init_auth(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    **kwargs
) -> MicrocosmAuth:
    """
    初始化认证客户端

    Args:
        client_id: OAuth Client ID
        client_secret: OAuth Client Secret
        auth_endpoint: 认证服务地址
        **kwargs: 其他参数

    Returns:
        MicrocosmAuth 实例
    """
    global _auth_instance
    _auth_instance = MicrocosmAuth(
        client_id=client_id,
        client_secret=client_secret,
        auth_endpoint=auth_endpoint,
        **kwargs
    )
    # 同时初始化全局实例
    _init_auth(client_id, client_secret, auth_endpoint, **kwargs)
    return _auth_instance


def get_auth_instance() -> MicrocosmAuth:
    """获取 FastAPI 模块的认证实例"""
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
    """
    FastAPI 依赖: 获取当前用户 (必须登录)

    用法:
        @app.get('/api/protected')
        async def protected_route(user: User = Depends(get_current_user)):
            return {'message': f'Hello {user.email}'}

    Raises:
        HTTPException 401: 未提供 token 或 token 无效
    """
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
    """
    FastAPI 依赖: 可选的用户认证 (不强制登录)

    用法:
        @app.get('/api/public')
        async def public_route(user: Optional[User] = Depends(get_optional_user)):
            if user:
                return {'message': f'Hello {user.email}'}
            return {'message': 'Hello guest'}

    Returns:
        User 对象（如果已登录），否则 None
    """
    if not credentials:
        return None

    auth = get_auth_instance()
    return auth.verify_token(credentials.credentials)


def require_role(*roles: str):
    """
    FastAPI 依赖工厂: 要求特定角色

    用法:
        @app.get('/api/admin')
        async def admin_route(user: User = Depends(require_role('admin'))):
            return {'message': 'Admin only'}

        @app.get('/api/staff')
        async def staff_route(user: User = Depends(require_role('admin', 'trader'))):
            return {'message': 'Staff only'}

    Args:
        *roles: 允许的角色列表

    Raises:
        HTTPException 401: 未登录
        HTTPException 403: 权限不足
    """
    async def check_role(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f'Insufficient permissions. Required role: {", ".join(roles)}',
            )
        return user

    return check_role


def require_admin(user: User = Depends(get_current_user)) -> User:
    """
    FastAPI 依赖: 要求管理员权限

    用法:
        @app.get('/api/admin')
        async def admin_route(user: User = Depends(require_admin)):
            return {'message': 'Admin only'}
    """
    if not user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Admin access required',
        )
    return user


async def get_user_and_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Tuple[User, str]:
    """
    FastAPI 依赖: 获取用户和原始 token

    用法:
        @app.get('/api/proxy')
        async def proxy_route(user_token: Tuple[User, str] = Depends(get_user_and_token)):
            user, token = user_token
            # 可以用 token 调用其他服务
    """
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


# 便捷别名
CurrentUser = Depends(get_current_user)
OptionalUser = Depends(get_optional_user)
AdminUser = Depends(require_admin)


# 导出
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
