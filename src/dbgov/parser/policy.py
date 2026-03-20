from __future__ import annotations

import glob as globmod
import os
import secrets
import string
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from dbgov.models.grant import CreatePrincipalSpec, GrantSpec
from dbgov.models.policy import PolicyDocument, PrincipalDocument


class ParsedPolicies:
    """Container for parsed principals and grant specs."""

    def __init__(self) -> None:
        self.principals: list[CreatePrincipalSpec] = []
        self.grants: list[GrantSpec] = []


def parse_policy_file(path: str | Path) -> list[GrantSpec]:
    """Parse a single policy file and return grant specs (legacy compat)."""
    parsed = parse_file(path)
    return parsed.grants


def parse_file(path: str | Path) -> ParsedPolicies:
    """Parse a single policy file and return both principals and grants."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        doc = yaml.safe_load(f)

    result = ParsedPolicies()
    kind = doc.get("kind", "")

    if kind == "Principal":
        principal_doc = PrincipalDocument.model_validate(doc)
        result.principals.append(_principal_doc_to_spec(principal_doc))
    elif kind == "AccessPolicy":
        policy_doc = PolicyDocument.model_validate(doc)
        result.grants.extend(_policy_doc_to_specs(policy_doc))
    else:
        raise ValueError(f"Unknown document kind: {kind}")

    return result


def parse_policy_glob(pattern: str) -> list[GrantSpec]:
    """Parse a glob pattern and return grant specs (legacy compat)."""
    parsed = parse_glob(pattern)
    return parsed.grants


def parse_glob(pattern: str) -> ParsedPolicies:
    """Parse a glob pattern and return both principals and grants."""
    files = sorted(globmod.glob(pattern, recursive=True))
    if not files:
        raise FileNotFoundError(f"No policy files found matching: {pattern}")

    result = ParsedPolicies()
    for file_path in files:
        parsed = parse_file(file_path)
        result.principals.extend(parsed.principals)
        result.grants.extend(parsed.grants)
    return result


def _resolve_password(spec: PrincipalDocument) -> str | None:
    """Resolve the password based on the strategy."""
    pw = spec.spec.password
    if pw.strategy == "none":
        return None
    if pw.strategy == "fromEnv":
        assert pw.env_var is not None
        value = os.environ.get(pw.env_var)
        if not value:
            raise ValueError(f"Environment variable '{pw.env_var}' is not set or empty")
        return value
    if pw.strategy == "randomize":
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(alphabet) for _ in range(24))
    return None


def _principal_doc_to_spec(doc: PrincipalDocument) -> CreatePrincipalSpec:
    return CreatePrincipalSpec(
        name=doc.spec.name,
        type=doc.spec.type,
        password=_resolve_password(doc),
        options=doc.spec.options,
    )


def _policy_doc_to_specs(doc: PolicyDocument) -> list[GrantSpec]:
    principal = doc.spec.principal
    expires_at = doc.spec.expires_at

    return [
        GrantSpec(
            db_principal=principal.name,
            principal_type=principal.type,
            schema_name=grant.schema_ or "",
            table_names=grant.tables,
            privileges=grant.privileges,
            grant_level=grant.level,
            expires_at=expires_at,
        )
        for grant in doc.spec.grants
    ]
