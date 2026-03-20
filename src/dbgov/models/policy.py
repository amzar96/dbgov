from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class PolicyMetadata(BaseModel):
    name: str


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
    metadata: PolicyMetadata
    spec: PolicySpec

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        if not v.startswith("dbgov/"):
            raise ValueError(f"Unsupported apiVersion: {v}")
        return v
