# Microcosm Auth SDK for Python

一个简单、安全的 Python 认证库，让任何项目通过几行代码接入 Microcosm 认证系统。

## 特性

- **零配置启动** - 只需 `client_id` 即可运行
- **多框架支持** - Flask 和 FastAPI 开箱即用
- **自动 Token 缓存** - 减少 introspect 调用
- **类型安全** - 完整的类型注解
- **安全第一** - 遵循 OAuth 2.0 最佳实践

## 安装

```bash
# 基础安装
pip install microcosm-auth

# Flask 支持
pip install microcosm-auth[flask]

# FastAPI 支持
pip install microcosm-auth[fastapi]

# 完整安装
pip install microcosm-auth[all]
```

## 快速开始

### Flask

```python
from flask import Flask, jsonify
from microcosm_auth import MicrocosmAuth

app = Flask(__name__)
auth = MicrocosmAuth(client_id='your_client_id')

@app.route('/api/protected')
@auth.require_auth
def protected_route():
    user = auth.current_user
    return jsonify({'message': f'Hello {user.email}'})

@app.route('/api/admin')
@auth.require_role('admin')
def admin_route():
    return jsonify({'message': 'Admin only'})
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from microcosm_auth.fastapi import init_auth, get_current_user, require_role, User

app = FastAPI()
init_auth(client_id='your_client_id')

@app.get('/api/protected')
async def protected_route(user: User = Depends(get_current_user)):
    return {'message': f'Hello {user.email}'}

@app.get('/api/admin')
async def admin_route(user: User = Depends(require_role('admin'))):
    return {'message': 'Admin only'}
```

## 配置

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `MICROCOSM_CLIENT_ID` | OAuth Client ID | - |
| `MICROCOSM_CLIENT_SECRET` | OAuth Client Secret | - |
| `MICROCOSM_AUTH_ENDPOINT` | 认证服务地址 | `https://microcosm.money` |

### 构造函数参数

```python
auth = MicrocosmAuth(
    client_id='your_client_id',        # OAuth Client ID
    client_secret='your_secret',       # OAuth Client Secret (可选)
    auth_endpoint='https://...',       # 认证服务地址
    cache_ttl=60,                      # Token 缓存时间（秒）
    debug=False,                       # 调试模式
)
```

## API 参考

### MicrocosmAuth

核心认证类，支持 Flask 和通用 Python 应用。

#### 方法

| 方法 | 说明 |
|------|------|
| `verify_token(token)` | 验证 Access Token，返回 User 或 None |
| `introspect_token(token)` | 调用 introspect API，返回 TokenInfo |
| `require_auth` | Flask 装饰器，要求登录 |
| `require_role(*roles)` | Flask 装饰器，要求特定角色 |
| `current_user` | 当前请求的用户（需先调用 require_auth） |
| `clear_cache()` | 清除 Token 缓存 |

### FastAPI 依赖

| 依赖 | 说明 |
|------|------|
| `get_current_user` | 获取当前用户（必须登录） |
| `get_optional_user` | 获取当前用户（可选登录） |
| `require_role(*roles)` | 要求特定角色 |
| `require_admin` | 要求管理员权限 |

### User 对象

```python
@dataclass
class User:
    uid: str                    # 用户 ID
    email: str                  # 邮箱
    role: str                   # 角色 (admin/trader/user)
    display_name: str | None    # 显示名称
    avatar_url: str | None      # 头像 URL
    email_verified: bool        # 邮箱是否验证
    station_id: int | None      # 站点 ID
```

## 错误处理

SDK 定义了以下异常类：

| 异常 | HTTP 状态 | 说明 |
|------|----------|------|
| `UnauthorizedError` | 401 | 未提供认证信息 |
| `InvalidTokenError` | 401 | Token 无效 |
| `TokenExpiredError` | 401 | Token 已过期 |
| `ForbiddenError` | 403 | 权限不足 |
| `ConfigurationError` | 500 | SDK 未配置 |
| `IntrospectError` | 500 | Introspect API 调用失败 |

## 最佳实践

### 1. 使用环境变量

```bash
export MICROCOSM_CLIENT_ID=your_client_id
export MICROCOSM_CLIENT_SECRET=your_secret
```

```python
# 自动从环境变量读取
auth = MicrocosmAuth()
```

### 2. 生产环境使用 Redis 缓存

默认使用内存缓存，生产环境建议配置 Redis：

```python
# TODO: Redis 缓存支持将在 v0.2.0 添加
```

### 3. 调试模式

开发时启用调试日志：

```python
auth = MicrocosmAuth(debug=True)
```

## 许可证

MIT License

## 链接

- [GitHub](https://github.com/microcosm-platform/microcosm-auth-python)
- [文档](https://microcosm.money/docs/auth-sdk)
- [问题反馈](https://github.com/microcosm-platform/microcosm-auth-python/issues)
