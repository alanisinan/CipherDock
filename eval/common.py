"""Shared label parsing and identifier matching for evaluation scripts."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

IDENTIFIER_COLUMNS = (
    "sha256",
    "ipa_relative_path",
    "relative_path",
    "ipa_file",
    "ipa",
    "filename",
    "file",
    "sample",
    "app",
    "bundle_identifier",
    "bundle_id",
    "path",
)
LABEL_COLUMNS = (
    "label",
    "ground_truth",
    "is_positive",
    "positive",
    "malicious",
    "vulnerable",
    "expected",
)
POSITIVE_LABELS = {"1", "true", "yes", "positive", "risky", "risk", "vulnerable", "malicious", "unsafe"}
NEGATIVE_LABELS = {"0", "false", "no", "negative", "benign", "clean", "safe"}
CORPUS_LABEL_FIELDS = (
    "app_id",
    "relative_path",
    "ipa_file",
    "sha256",
    "label",
    "benchmark_role",
    "variant_type",
    "base_sha256",
    "behaviors",
    "source",
    "status",
)


@dataclass(frozen=True)
class LabelMatch:
    label: int
    key: str


class LabelIndex:
    def __init__(self, values: Dict[str, Optional[int]]) -> None:
        self._values = values

    def match(self, candidates: Iterable[str]) -> Optional[LabelMatch]:
        for candidate in candidates:
            for key in _lookup_keys(candidate):
                label = self._values.get(key)
                if label is not None:
                    return LabelMatch(label=label, key=key)
        return None


def load_labels(path: Path) -> LabelIndex:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = [str(name).strip() for name in (reader.fieldnames or [])]
        normalized = {name.lower(): name for name in headers}
        identifier_columns = [normalized[name] for name in IDENTIFIER_COLUMNS if name in normalized]
        label_column = _column(normalized, LABEL_COLUMNS)
        if not identifier_columns or label_column is None:
            raise ValueError(
                "labels.csv must include an identifier column "
                f"({', '.join(IDENTIFIER_COLUMNS)}) and a label column ({', '.join(LABEL_COLUMNS)})"
            )
        values: Dict[str, Optional[int]] = {}
        for row_number, row in enumerate(reader, start=2):
            identifiers = [
                str(row.get(identifier_column, "")).strip()
                for identifier_column in identifier_columns
                if str(row.get(identifier_column, "")).strip()
            ]
            if not identifiers:
                raise ValueError(f"labels.csv row {row_number} has no sample identifier")
            label = parse_label(str(row.get(label_column, "")), row_number)
            for identifier in identifiers:
                for key in _lookup_keys(identifier):
                    if key not in values:
                        values[key] = label
                    elif values[key] != label:
                        # A short name can be ambiguous across nested corpus paths.
                        values[key] = None
    return LabelIndex(values)


def parse_label(value: str, row_number: int = 0) -> int:
    normalized = value.strip().lower()
    if normalized in POSITIVE_LABELS:
        return 1
    if normalized in NEGATIVE_LABELS:
        return 0
    location = f" on row {row_number}" if row_number else ""
    raise ValueError(f"Unsupported binary label{location}: {value!r}")


def read_label_rows(path: Path) -> list[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def upsert_label_rows(path: Path, new_rows: Iterable[Dict[str, str]]) -> None:
    rows = read_label_rows(path)
    positions = {
        str(row.get("relative_path") or row.get("ipa_file") or row.get("app_id")): index
        for index, row in enumerate(rows)
    }
    for raw_row in new_rows:
        row = {field: str(raw_row.get(field, "")) for field in CORPUS_LABEL_FIELDS}
        key = row["relative_path"] or row["ipa_file"] or row["app_id"]
        if key in positions:
            rows[positions[key]] = row
        else:
            positions[key] = len(rows)
            rows.append(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CORPUS_LABEL_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def sample_candidates(
    *,
    sha256: str = "",
    relative_path: str = "",
    filename: str = "",
    bundle_identifier: str = "",
) -> Tuple[str, ...]:
    candidates = [sha256, relative_path, filename, bundle_identifier]
    return tuple(value for value in candidates if value)


def _column(headers: Dict[str, str], choices: Sequence[str]) -> Optional[str]:
    for choice in choices:
        if choice in headers:
            return headers[choice]
    return None


def _lookup_keys(value: str) -> Tuple[str, ...]:
    normalized = value.strip().replace("\\", "/").lower()
    if not normalized:
        return ()
    if re.fullmatch(r"[0-9a-f]{64}", normalized):
        return (normalized,)
    basename = normalized.rsplit("/", 1)[-1]
    stem = basename[:-4] if basename.endswith(".ipa") else basename
    return tuple(dict.fromkeys((normalized, basename, stem)))
