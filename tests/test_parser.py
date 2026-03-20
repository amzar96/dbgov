from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from dbgov.parser.policy import parse_policy_file, parse_policy_glob

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseValidFiles:
    def test_table_level_policy(self) -> None:
        specs = parse_policy_file(FIXTURES / "analyst-finance.yaml")
        assert len(specs) == 1
        spec = specs[0]
        assert spec.db_principal == "analyst_user"
        assert spec.principal_type == "user"
        assert spec.schema_name == "public"
        assert spec.table_names == ["transactions", "accounts"]
        assert spec.privileges == ["SELECT"]
        assert spec.grant_level == "table"

    def test_schema_level_policy(self) -> None:
        specs = parse_policy_file(FIXTURES / "schema-level.yaml")
        assert len(specs) == 1
        spec = specs[0]
        assert spec.db_principal == "etl_user"
        assert spec.grant_level == "schema"
        assert spec.table_names == []
        assert spec.privileges == ["SELECT"]

    def test_privileges_uppercased(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(
                "apiVersion: dbgov/v1\n"
                "kind: AccessPolicy\n"
                "metadata:\n"
                "  name: test\n"
                "spec:\n"
                "  principal:\n"
                "    name: usr\n"
                "    type: user\n"
                "  grants:\n"
                "    - level: table\n"
                "      schema: public\n"
                "      tables:\n"
                "        - t1\n"
                "      privileges:\n"
                "        - select\n"
                "        - insert\n"
            )
            f.flush()
            specs = parse_policy_file(f.name)
        assert specs[0].privileges == ["SELECT", "INSERT"]


class TestParseInvalidFiles:
    def test_missing_principal_name(self) -> None:
        with pytest.raises(ValueError, match=r"principal\.name"):
            parse_policy_file(FIXTURES / "invalid-no-principal.yaml")

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_policy_file("/nonexistent/path.yaml")

    def test_bad_api_version(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("apiVersion: wrong/v1\nkind: AccessPolicy\nspec: {}\n")
            f.flush()
            with pytest.raises(ValueError, match="Unsupported apiVersion"):
                parse_policy_file(f.name)

    def test_bad_kind(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("apiVersion: dbgov/v1\nkind: WrongKind\nspec: {}\n")
            f.flush()
            with pytest.raises(ValueError, match="kind"):
                parse_policy_file(f.name)

    def test_table_level_missing_tables(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(
                "apiVersion: dbgov/v1\n"
                "kind: AccessPolicy\n"
                "metadata:\n"
                "  name: test\n"
                "spec:\n"
                "  principal:\n"
                "    name: usr\n"
                "    type: user\n"
                "  grants:\n"
                "    - level: table\n"
                "      schema: public\n"
                "      privileges:\n"
                "        - SELECT\n"
            )
            f.flush()
            with pytest.raises(ValueError, match="requires at least one table"):
                parse_policy_file(f.name)

    def test_missing_privileges(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(
                "apiVersion: dbgov/v1\n"
                "kind: AccessPolicy\n"
                "metadata:\n"
                "  name: test\n"
                "spec:\n"
                "  principal:\n"
                "    name: usr\n"
                "    type: user\n"
                "  grants:\n"
                "    - level: table\n"
                "      schema: public\n"
                "      tables:\n"
                "        - t1\n"
            )
            f.flush()
            with pytest.raises(ValueError, match="privileges"):
                parse_policy_file(f.name)


class TestParseGlob:
    def test_glob_finds_fixtures(self) -> None:
        valid_dir = tempfile.mkdtemp()
        for name in ("analyst-finance.yaml", "schema-level.yaml"):
            src = FIXTURES / name
            dst = Path(valid_dir) / name
            dst.write_text(src.read_text())
        specs = parse_policy_glob(f"{valid_dir}/*.yaml")
        assert len(specs) >= 2

    def test_glob_no_match(self) -> None:
        with pytest.raises(FileNotFoundError, match="No policy files found"):
            parse_policy_glob("/nonexistent/*.yaml")
