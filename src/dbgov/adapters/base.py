from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from dbgov.models.grant import (
        AdapterResult,
        CreatePrincipalSpec,
        GrantSpec,
        PermissionRecord,
        RoleMembershipSpec,
    )
    from dbgov.settings.config import AppSettings


class BaseAdapter(ABC):
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def __enter__(self) -> BaseAdapter:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.disconnect()

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def create_principal(self, spec: CreatePrincipalSpec) -> AdapterResult: ...

    @abstractmethod
    def grant(self, spec: GrantSpec) -> AdapterResult: ...

    @abstractmethod
    def revoke(self, spec: GrantSpec) -> AdapterResult: ...

    @abstractmethod
    def list_permissions(
        self,
        schema: str | None = None,
        principal: str | None = None,
    ) -> list[PermissionRecord]: ...

    @abstractmethod
    def principal_exists(self, db_principal: str) -> bool: ...

    @abstractmethod
    def role_members(self, role: str) -> list[str]: ...

    @abstractmethod
    def grant_role(self, spec: RoleMembershipSpec) -> AdapterResult: ...

    @abstractmethod
    def test_connection(self) -> bool: ...
