from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Union


@dataclass(frozen=True)
class LDAPUser:
    dn: str = field(metadata={"description": "Distinguished Name of the user"})
    username: str = field(metadata={"description": "Username (uid or sAMAccountName)"})
    email: Optional[str] = field(
        default=None, metadata={"description": "Email address"}
    )
    display_name: Optional[str] = field(
        default=None, metadata={"description": "Display name"}
    )
    groups: FrozenSet[str] = field(
        default_factory=frozenset,
        metadata={"description": "Set of group names the user belongs to"},
    )
    attributes: dict[str, Union[str, list[str]]] = field(
        default_factory=dict,
        metadata={"description": "Additional LDAP attributes"},
    )

    def has_group(self, group: str) -> bool:
        return group in self.groups

    def has_any_group(self, groups: set[str]) -> bool:
        return bool(self.groups & groups)

    def has_all_groups(self, groups: set[str]) -> bool:
        return groups.issubset(self.groups)

