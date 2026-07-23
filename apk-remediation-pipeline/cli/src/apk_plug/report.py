"""Threat report data model and schema validation."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import jsonschema

logger = logging.getLogger(__name__)

# Path to schema relative to package
SCHEMA_PATH = Path(__file__).parent.parent.parent.parent / "assets" / "threat-report.schema.json"


class ToolStatus(Enum):
    """Status of a scanner tool execution."""

    RAN = "ran"
    NOT_RUN = "not_run"
    ERROR = "error"


class RiskLevel(Enum):
    """Aggregate risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolResult:
    """Result from a single scanner tool."""

    status: ToolStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    raw_output_path: str | None = None


@dataclass
class Component:
    """An Android component (receiver, service, activity, provider)."""

    type: str  # receiver, service, activity, provider
    name: str
    source_tool: str
    exported: bool | None = None
    permission: str | None = None


@dataclass
class MitreTechnique:
    """A MITRE ATT&CK technique reference."""

    id: str
    name: str


@dataclass
class AggregateRisk:
    """Aggregate risk assessment."""

    score: int  # 0-100
    level: RiskLevel
    drivers: list[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    """Unified threat report combining all scanner outputs."""

    schema_version: str
    apk: dict[str, str]  # name, sha256
    generated_at: str
    tools: dict[str, dict[str, Any]]
    components: list[dict[str, Any]]
    urls: list[str]
    permissions: list[str]
    mitre_techniques: list[dict[str, str]]
    findings: dict[str, list[dict[str, Any]]]
    aggregate_risk: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "schema_version": self.schema_version,
            "apk": self.apk,
            "generated_at": self.generated_at,
            "tools": self.tools,
            "components": self.components,
            "urls": self.urls,
            "permissions": self.permissions,
            "mitre_techniques": self.mitre_techniques,
            "findings": self.findings,
            "aggregate_risk": self.aggregate_risk,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert report to JSON string with sorted keys for stability."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"


class SchemaValidationError(Exception):
    """Raised when a threat report fails schema validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Schema validation failed: {'; '.join(errors[:3])}")


def load_schema(schema_path: Path | None = None) -> dict[str, Any]:
    """
    Load the threat report JSON schema.

    Args:
        schema_path: Override path to schema file.

    Returns:
        Parsed JSON schema as dict.
    """
    if schema_path is None:
        schema_path = SCHEMA_PATH

    if not schema_path.exists():
        msg = f"Schema file not found: {schema_path}"
        raise FileNotFoundError(msg)

    return json.loads(schema_path.read_text())


def validate_report(report: dict[str, Any], schema_path: Path | None = None) -> None:
    """
    Validate a threat report against the JSON schema.

    Args:
        report: The report dictionary to validate.
        schema_path: Override path to schema file.

    Raises:
        SchemaValidationError: If validation fails.
    """
    schema = load_schema(schema_path)

    validator = jsonschema.Draft7Validator(schema)
    errors = list(validator.iter_errors(report))

    if errors:
        error_messages = [f"{e.json_path}: {e.message}" for e in errors[:5]]
        raise SchemaValidationError(error_messages)

    logger.debug("Report validated against schema")
