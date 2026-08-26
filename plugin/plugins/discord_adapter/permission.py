"""
Discord adapter permission management module.

Manages per-Discord-user permission levels: admin / trusted / normal / none.
Mirrors the bilibili_dm PermissionManager with Discord user IDs (snowflake
strings) instead of Bilibili UIDs.
"""

from typing import Dict, List, Optional


class PermissionManager:
    """Permission manager keyed by Discord user ID strings."""

    VALID_LEVELS = {"admin", "trusted", "normal"}

    def __init__(self, trusted_users: Optional[List[Dict[str, str]]] = None):
        """Initialize the manager from a persisted user list.

        Args:
            trusted_users: Entries like
                {"uid": "1234567890", "level": "admin", "nickname": "Alice"}.
        """
        self._users: Dict[str, str] = {}      # {uid: level}
        self._nicknames: Dict[str, str] = {}  # {uid: nickname}

        if trusted_users:
            for user in trusted_users:
                uid = self._normalize_uid(user.get("uid", ""))
                level = self._normalize_level(user.get("level", ""))
                nickname = user.get("nickname", "")
                if uid and level:
                    self._users[uid] = level
                    if nickname and level != "admin":
                        self._nicknames[uid] = nickname

    @staticmethod
    def _normalize_uid(uid: str) -> str:
        return str(uid or "").strip()

    @classmethod
    def _normalize_level(cls, level: str) -> Optional[str]:
        level_text = str(level or "").strip().lower()
        return level_text if level_text in cls.VALID_LEVELS else None

    def add_user(self, uid: str, level: str = "trusted", nickname: str = "") -> bool:
        """Add or update a user. Returns False on invalid input."""
        uid_str = self._normalize_uid(uid)
        if not uid_str or not uid_str.isdigit():
            return False
        normalized = self._normalize_level(level)
        if not normalized:
            return False
        self._users[uid_str] = normalized
        if normalized == "admin":
            # Admins are always addressed as the master; custom nicknames are
            # meaningless for them.
            self._nicknames.pop(uid_str, None)
        elif nickname:
            self._nicknames[uid_str] = nickname
        return True

    def remove_user(self, uid: str) -> None:
        """Remove a user from the list."""
        uid_str = self._normalize_uid(uid)
        self._users.pop(uid_str, None)
        self._nicknames.pop(uid_str, None)

    def get_permission_level(self, uid: str) -> str:
        """Return one of: admin, trusted, normal, none."""
        uid_str = self._normalize_uid(uid)
        return self._users.get(uid_str, "none")

    def list_users(self) -> List[Dict[str, str]]:
        """List every registered user."""
        result = []
        for uid, level in self._users.items():
            user_info = {"uid": uid, "level": level}
            if uid in self._nicknames:
                user_info["nickname"] = self._nicknames[uid]
            result.append(user_info)
        return result

    def get_nickname(self, uid: str) -> Optional[str]:
        """Return the custom nickname for a user, if any."""
        return self._nicknames.get(self._normalize_uid(uid))

    def set_nickname(self, uid: str, nickname: str) -> bool:
        """Set or clear a custom nickname for a registered user."""
        uid_str = self._normalize_uid(uid)
        if uid_str in self._users:
            if nickname:
                self._nicknames[uid_str] = nickname
            else:
                self._nicknames.pop(uid_str, None)
            return True
        return False

    def is_admin(self, uid: str) -> bool:
        """Check whether the user is an admin."""
        return self.get_permission_level(uid) == "admin"

    def is_trusted(self, uid: str) -> bool:
        """Check whether the user is trusted (admins count as trusted)."""
        return self.get_permission_level(uid) in ("admin", "trusted")

    def should_process(self, uid: str, permission_mode: str = "allow_list") -> bool:
        """Decide whether a message from this user should be processed.

        allow_list: only listed users (admin/trusted/normal).
        deny_list: everyone except users listed as normal (the blacklist tier).
        open: everyone.
        """
        level = self.get_permission_level(uid)
        if permission_mode == "allow_list":
            return level != "none"
        if permission_mode == "deny_list":
            return level != "normal"
        return permission_mode == "open"
