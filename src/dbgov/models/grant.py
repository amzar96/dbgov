from __future__ import annotations

from pydantic import BaseModel


class CreatePrincipalSpec(BaseModel):
    model_config = {"frozen": True}

    name: str
    type: str = "user"
    password: str | None = None
    options: list[str] = []


class GrantSpec(BaseModel):
    model_config = {"frozen": True}

    db_principal: str
    principal_type: str
    schema_name: str
    table_names: list[str]
    privileges: list[str]
    grant_level: str
    expires_at: str | None = None


class AdapterResult(BaseModel):
    success: bool
    executed_sql: list[str] = []
    error: str | None = None


class PermissionRecord(BaseModel):
    model_config = {"frozen": True}

    principal: str
    schema_name: str
    table_name: str | None
    privilege: str


class PlanRow(BaseModel):
    model_config = {"frozen": True}

    action: str
    principal: str
    schema_name: str
    table: str
    privilege: str
