# microcosm_auth/models.py
"""
Microcosm Auth SDK - Data Models
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class User:
    """Microcosm 用户对象"""
    uid: str
    email: str
    role: str
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    email_verified: bool = False
    station_id: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            'uid': self.uid,
            'email': self.email,
            'role': self.role,
            'display_name': self.display_name,
            'avatar_url': self.avatar_url,
            'email_verified': self.email_verified,
            'station_id': self.station_id,
        }
        if self.extra:
            result.update(self.extra)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """从字典创建用户对象"""
        known_keys = {'uid', 'email', 'role', 'display_name', 'avatar_url',
                      'email_verified', 'station_id'}
        extra = {k: v for k, v in data.items() if k not in known_keys}

        return cls(
            uid=data.get('uid', ''),
            email=data.get('email', ''),
            role=data.get('role', 'user'),
            display_name=data.get('display_name'),
            avatar_url=data.get('avatar_url'),
            email_verified=data.get('email_verified', False),
            station_id=data.get('station_id'),
            extra=extra,
        )

    def has_role(self, *roles: str) -> bool:
        """检查用户是否拥有指定角色之一"""
        return self.role in roles

    def is_admin(self) -> bool:
        """是否为管理员"""
        return self.role == 'admin'


@dataclass
class TokenInfo:
    """Token 信息"""
    active: bool
    user: Optional[User] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    scope: Optional[str] = None
    client_id: Optional[str] = None

    @classmethod
    def from_introspect(cls, data: Dict[str, Any]) -> 'TokenInfo':
        """从 introspect API 响应创建"""
        user = None
        if data.get('active'):
            user = User.from_dict(data)

        return cls(
            active=data.get('active', False),
            user=user,
            exp=data.get('exp'),
            iat=data.get('iat'),
            scope=data.get('scope'),
            client_id=data.get('client_id'),
        )
