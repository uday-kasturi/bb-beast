"""
Schema validator. Runs before any file passes between pipeline stages.
All 9 schemas are loaded once at import time and cached.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft7Validator, ValidationError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema registry
# ---------------------------------------------------------------------------

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"

_SCHEMA_FILES = {
    "program":            "program.schema.json",
    "playbook_manifest":  "playbook_manifest.schema.json",
    "raw_output":         "raw_output.schema.json",
    "findings":           "findings.schema.json",
    "triage":             "triage.schema.json",
    "actions":            "actions.schema.json",
    "playbook_patch":     "playbook_patch.schema.json",
    "threat_alert":       "threat_alert.schema.json",
    "run_manifest":       "run_manifest.schema.json",
    "agent_message":      "agent_message.schema.json",
}

_SCHEMA_CACHE: dict[str, dict] = {}


def _load_schemas() -> None:
    """Load all schemas from disk into the cache. Called once at import."""
    for name, filename in _SCHEMA_FILES.items():
        path = SCHEMA_DIR / filename
        if not path.exists():
            raise FileNotFoundError(f"Schema file not found: {path}")
        with open(path) as f:
            _SCHEMA_CACHE[name] = json.load(f)
    log.debug("Loaded %d schemas from %s", len(_SCHEMA_CACHE), SCHEMA_DIR)


_load_schemas()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SchemaValidationError(Exception):
    """Raised when a document fails schema validation."""

    def __init__(self, schema_name: str, errors: list[str]) -> None:
        self.schema_name = schema_name
        self.errors = errors
        msg = f"Validation failed for schema '{schema_name}':\n" + "\n".join(
            f"  - {e}" for e in errors
        )
        super().__init__(msg)


def validate(schema_name: str, document: Any) -> None:
    """
    Validate *document* against the named schema.

    Args:
        schema_name: One of the keys in _SCHEMA_FILES.
        document:    Parsed Python object (dict, list, etc.).

    Raises:
        SchemaValidationError: If validation fails. Contains all errors.
        KeyError: If schema_name is unknown.
    """
    if schema_name not in _SCHEMA_CACHE:
        raise KeyError(
            f"Unknown schema '{schema_name}'. "
            f"Valid names: {sorted(_SCHEMA_CACHE)}"
        )

    schema = _SCHEMA_CACHE[schema_name]
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))

    if errors:
        messages = [_format_error(e) for e in errors]
        raise SchemaValidationError(schema_name, messages)


def validate_file(schema_name: str, path: Path | str) -> dict:
    """
    Load a JSON file and validate it.

    Args:
        schema_name: Schema to validate against.
        path:        Path to the JSON file.

    Returns:
        The parsed document if valid.

    Raises:
        SchemaValidationError: If validation fails.
        FileNotFoundError: If the file doesn't exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path) as f:
        document = json.load(f)

    validate(schema_name, document)
    log.debug("Validated %s against schema '%s' ✓", path.name, schema_name)
    return document


def validate_and_write(schema_name: str, document: Any, path: Path | str) -> None:
    """
    Validate *document* then write it to *path* as JSON.
    Nothing is written if validation fails.

    Args:
        schema_name: Schema to validate against.
        document:    Python object to validate and write.
        path:        Destination file path.

    Raises:
        SchemaValidationError: If validation fails.
    """
    validate(schema_name, document)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(document, f, indent=2)
    log.debug("Validated and wrote %s ✓", path.name)


def schema_names() -> list[str]:
    """Return all registered schema names."""
    return sorted(_SCHEMA_CACHE.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _format_error(error: ValidationError) -> str:
    """Format a jsonschema ValidationError into a readable string."""
    path = " → ".join(str(p) for p in error.absolute_path) if error.absolute_path else "root"
    return f"[{path}] {error.message}"
