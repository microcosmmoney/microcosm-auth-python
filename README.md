# Microcosm Auth SDK for Python

A simple, secure Python authentication library that lets any project integrate with the Microcosm auth system in just a few lines of code.

## Features

- **Zero-config startup** - Only a `client_id` is needed to get started
- **Multi-framework support** - Flask and FastAPI out of the box
- **Automatic token caching** - Reduces introspect API calls
- **Type safe** - Full type annotations
- **Security first** - Follows OAuth 2.0 best practices

## Installation

```bash
# Basic install
pip install microcosm-auth

# Flask support
pip install microcosm-auth[flask]

# FastAPI support
pip install microcosm-auth[fastapi]

# Full install
pip install microcosm-auth[all]
```

## Quick Start

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

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MICROCOSM_CLIENT_ID` | OAuth Client ID | - |
| `MICROCOSM_CLIENT_SECRET` | OAuth Client Secret | - |
| `MICROCOSM_AUTH_ENDPOINT` | Auth service URL | `https://microcosm.money` |

### Constructor Parameters

```python
auth = MicrocosmAuth(
    client_id='your_client_id',        # OAuth Client ID
    client_secret='your_secret',       # OAuth Client Secret (optional)
    auth_endpoint='https://...',       # Auth service URL
    cache_ttl=60,                      # Token cache duration (seconds)
    debug=False,                       # Debug mode
)
```

## API Reference

### MicrocosmAuth

Core authentication class supporting Flask and general Python applications.

#### Methods

| Method | Description |
|--------|-------------|
| `verify_token(token)` | Verify an access token, returns User or None |
| `introspect_token(token)` | Call introspect API, returns TokenInfo |
| `require_auth` | Flask decorator, requires authentication |
| `require_role(*roles)` | Flask decorator, requires specific role(s) |
| `current_user` | Current request user (requires prior `require_auth` call) |
| `clear_cache()` | Clear token cache |

### FastAPI Dependencies

| Dependency | Description |
|------------|-------------|
| `get_current_user` | Get current user (authentication required) |
| `get_optional_user` | Get current user (authentication optional) |
| `require_role(*roles)` | Require specific role(s) |
| `require_admin` | Require admin privileges |

### User Object

```python
@dataclass
class User:
    uid: str                    # User ID
    email: str                  # Email address
    role: str                   # Role (admin/trader/user)
    display_name: str | None    # Display name
    avatar_url: str | None      # Avatar URL
    email_verified: bool        # Whether email is verified
    station_id: int | None      # Station ID
```

## Error Handling

The SDK defines the following exception classes:

| Exception | HTTP Status | Description |
|-----------|-------------|-------------|
| `UnauthorizedError` | 401 | Missing authentication credentials |
| `InvalidTokenError` | 401 | Invalid token |
| `TokenExpiredError` | 401 | Token has expired |
| `ForbiddenError` | 403 | Insufficient permissions |
| `ConfigurationError` | 500 | SDK not configured |
| `IntrospectError` | 500 | Introspect API call failed |

## Best Practices

### 1. Use Environment Variables

```bash
export MICROCOSM_CLIENT_ID=your_client_id
export MICROCOSM_CLIENT_SECRET=your_secret
```

```python
# Automatically reads from environment variables
auth = MicrocosmAuth()
```

### 2. Use Redis Cache in Production

The default in-memory cache is suitable for development. For production, consider configuring Redis:

```python
# Redis cache support coming in v0.2.0
```

### 3. Debug Mode

Enable debug logging during development:

```python
auth = MicrocosmAuth(debug=True)
```

## License

MIT License

## Links

- [GitHub](https://github.com/microcosmmoney/microcosm-auth-python)
- [Documentation](https://microcosm.money/docs/auth-sdk)
- [Issue Tracker](https://github.com/microcosmmoney/microcosm-auth-python/issues)
