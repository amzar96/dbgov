from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class DocumentMetadata(BaseModel):
    name: str


class PasswordSpec(BaseModel):
    strategy: Literal["fromEnv", "randomize", "none"] = "none"
    env_var: str | None = Field(default=None, alias="envVar")

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def validate_env_var(self) -> PasswordSpec:
        if self.strategy == "fromEnv" and not self.env_var:
            raise ValueError("envVar is required when strategy is 'fromEnv'")
        return self


class PrincipalSpec(BaseModel):
    name: str
    type: Literal["user", "role"] = "user"
    password: PasswordSpec = PasswordSpec()
    options: list[str] = []


class PrincipalDocument(BaseModel):
    api_version: str = Field(alias="apiVersion")
    kind: Literal["Principal"]
    metadata: DocumentMetadata
    spec: PrincipalSpec

    model_config = {"populate_by_name": True}

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        if not v.startswith("dbgov/"):
            raise ValueError(f"Unsupported apiVersion: {v}")
        return v


class RoleBindingSpec(BaseModel):
    role: str
    members: list[str]


class RoleBindingDocument(BaseModel):
    api_version: str = Field(alias="apiVersion")
    kind: Literal["RoleBinding"]
    metadata: DocumentMetadata
    spec: RoleBindingSpec

    model_config = {"populate_by_name": True}

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        if not v.startswith("dbgov/"):
            raise ValueError(f"Unsupported apiVersion: {v}")
        return v


class PolicyPrincipal(BaseModel):
    name: str
    type: str = "user"


class PolicyGrant(BaseModel):
    level: Literal["table", "schema", "database"] = "table"
    schema_: str | None = None
    tables: list[str] = []
    privileges: list[str]

    model_config = {"populate_by_name": True}

    def __init__(self, **data: object) -> None:
        if "schema" in data:
            data["schema_"] = data.pop("schema")
        super().__init__(**data)

    @field_validator("privileges", mode="before")
    @classmethod
    def uppercase_privileges(cls, v: list[str]) -> list[str]:
        return [p.upper() for p in v]

    @model_validator(mode="after")
    def validate_grant(self) -> PolicyGrant:
        if self.level != "database" and not self.schema_:
            raise ValueError(f"Missing schema for {self.level}-level grant")
        if self.level == "table" and not self.tables:
            raise ValueError("Table-level grant requires at least one table")
        return self


class PolicySpec(BaseModel):
    principal: PolicyPrincipal
    grants: list[PolicyGrant]
    expires_at: str | None = None


class PolicyDocument(BaseModel):
    api_version: str = Field(alias="apiVersion")
    kind: Literal["AccessPolicy"]
    metadata: DocumentMetadata
    spec: PolicySpec

    model_config = {"populate_by_name": True}

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        if not v.startswith("dbgov/"):
            raise ValueError(f"Unsupported apiVersion: {v}")
        return v
