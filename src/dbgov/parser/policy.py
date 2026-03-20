from __future__ import annotations

import glob as globmod
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from dbgov.models.grant import GrantSpec
from dbgov.models.policy import PolicyDocument


def parse_policy_file(path: str | Path) -> list[GrantSpec]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with open(path) as f:
        doc = yaml.safe_load(f)

    return _doc_to_specs(PolicyDocument.model_validate(doc))


def parse_policy_glob(pattern: str) -> list[GrantSpec]:
    files = sorted(globmod.glob(pattern, recursive=True))
    if not files:
        raise FileNotFoundError(f"No policy files found matching: {pattern}")

    specs: list[GrantSpec] = []
    for file_path in files:
        specs.extend(parse_policy_file(file_path))
    return specs


def _doc_to_specs(doc: PolicyDocument) -> list[GrantSpec]:
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
