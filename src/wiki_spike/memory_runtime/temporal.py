"""Deterministic IANA-timezone temporal resolution for Phase 4 (P4-02).

Relative expressions are resolved against an explicit UTC ``as_of_at`` and an
IANA timezone.  The result always carries an absolute UTC interval (when an
interval exists), precision, source, and the timezone database version used.
Naive timestamps are never persisted as resolved values.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
from pathlib import Path
import re
import unicodedata
from typing import ClassVar, Mapping, Protocol
from zoneinfo import TZPATH, ZoneInfo, ZoneInfoNotFoundError

from wiki_spike.memory_runtime.contracts import (
    JsonValue,
    canonical_bytes,
    canonical_integer,
    format_utc_timestamp,
    parse_utc_timestamp,
)
from wiki_spike.memory_runtime.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)

TEMPORAL_RESOLUTION_VERSION = "phase4-temporal-resolution-v1"
_TEMPORAL_DOMAIN = b"wiki.runtime.temporal-resolution.v1\x00"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_LOCAL_SECOND = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MONTH = re.compile(r"^\d{4}-\d{2}$")
_YEAR = re.compile(r"^\d{4}$")
_ROLLING = re.compile(r"^rolling:(0|[1-9][0-9]*)([dh])$")


class TemporalMode(str, Enum):
    NONE = "none"
    AS_OF = "as_of"
    INTERVAL = "interval"
    INSTANT = "instant"


class TemporalPrecision(str, Enum):
    UNSPECIFIED = "unspecified"
    SECOND = "second"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"
    ROLLING = "rolling"


class TemporalSource(str, Enum):
    NONE = "none"
    EXPLICIT_FIELD = "explicit_field"
    QUERY_TEXT = "query_text"


class TimezoneProvider(Protocol):
    @property
    def version(self) -> str: ...

    def get(self, name: str) -> ZoneInfo: ...


def _detect_system_tzdb_version() -> str:
    for root in TZPATH:
        candidate = Path(root) / "tzdata.zi"
        try:
            first = candidate.read_text("utf-8").splitlines()[0]
        except (OSError, IndexError, UnicodeError):
            continue
        match = re.fullmatch(r"# version ([A-Za-z0-9._-]+)", first.strip())
        if match:
            return f"system:{match.group(1)}"
    try:
        import tzdata  # type: ignore

        version = getattr(tzdata, "__version__", "unknown")
        return f"python-tzdata:{version}"
    except Exception:
        return "system:unversioned"


class SystemTimezoneProvider:
    def __init__(self) -> None:
        self._version = _detect_system_tzdb_version()

    @property
    def version(self) -> str:
        return self._version

    def get(self, name: str) -> ZoneInfo:
        if not isinstance(name, str):
            raise InvalidContractValue("timezone must be an IANA zone string")
        normalized = unicodedata.normalize("NFC", name)
        if not normalized or len(normalized) > 128 or normalized.startswith(("/", ".")) or ".." in normalized:
            raise InvalidContractValue("timezone must be a canonical IANA zone")
        try:
            zone = ZoneInfo(normalized)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise InvalidContractValue(f"unknown IANA timezone: {normalized}") from exc
        if zone.key != normalized:
            raise InvalidContractValue("timezone key changed during resolution")
        return zone


def _nonempty(value: object, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a non-empty string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or not normalized.strip() or len(normalized) > maximum:
        raise InvalidContractValue(f"{field} must be a bounded non-empty string")
    return normalized


def _optional_nonempty(value: object, field: str, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return _nonempty(value, field, maximum=maximum)


def _safe_code(value: object, field: str) -> str:
    text = _nonempty(value, field, maximum=128)
    if not _SAFE_CODE.fullmatch(text):
        raise InvalidContractValue(f"{field} must be a lowercase Runtime code")
    return text


def _hex64(value: object, field: str) -> str:
    text = _nonempty(value, field, maximum=64)
    if not _HEX64.fullmatch(text):
        raise InvalidContractValue(f"{field} must be lowercase SHA-256 hex")
    return text


def _strict_mapping(data: Mapping[str, object], allowed: set[str], required: set[str], label: str) -> dict[str, object]:
    if not isinstance(data, Mapping):
        raise InvalidContractValue(f"{label} must be an object")
    unknown = set(data) - allowed
    missing = required - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def _reason_codes(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue("reason_codes must be an array")
    result = tuple(_safe_code(item, "reason_code") for item in value)
    if tuple(sorted(set(result))) != result:
        raise InvalidContractValue("reason_codes must be sorted and unique")
    return result


def _identity_hash(payload: Mapping[str, object]) -> str:
    return sha256(_TEMPORAL_DOMAIN + canonical_bytes(payload)).hexdigest()


def _parse_date(value: str, field: str) -> date:
    if not _DATE.fullmatch(value):
        raise InvalidContractValue(f"{field} must be YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} is not a valid date") from exc
    if parsed.isoformat() != value:
        raise InvalidContractValue(f"{field} is not canonical")
    return parsed


def _parse_month(value: str) -> tuple[int, int]:
    if not _MONTH.fullmatch(value):
        raise InvalidContractValue("month expression must be YYYY-MM")
    year, month = map(int, value.split("-"))
    if not 1 <= month <= 12:
        raise InvalidContractValue("month expression is invalid")
    return year, month


def _parse_year(value: str) -> int:
    if not _YEAR.fullmatch(value):
        raise InvalidContractValue("year expression must be YYYY")
    year = int(value)
    if not 1 <= year <= 9999:
        raise InvalidContractValue("year expression is invalid")
    return year


def _next_month(year: int, month: int) -> tuple[int, int]:
    if month == 12:
        if year == 9999:
            raise InvalidContractValue("month interval exceeds supported datetime range")
        return year + 1, 1
    return year, month + 1


def _localize_strict(naive: datetime, zone: ZoneInfo, fold: str | None) -> datetime:
    candidates: dict[str, datetime] = {}
    for candidate_fold in (0, 1):
        aware = naive.replace(tzinfo=zone, fold=candidate_fold)
        utc_value = aware.astimezone(timezone.utc)
        round_trip = utc_value.astimezone(zone)
        if round_trip.replace(tzinfo=None) == naive and round_trip.fold == candidate_fold:
            candidates[str(candidate_fold)] = utc_value

    unique_instants = {value for value in candidates.values()}
    if not unique_instants:
        raise InvalidContractValue("local timestamp does not exist in the selected timezone")
    if len(unique_instants) > 1:
        if fold is None:
            raise InvalidContractValue("local timestamp is ambiguous; temporal_fold is required")
        if fold not in candidates:
            raise InvalidContractValue("temporal_fold is not valid for the ambiguous local timestamp")
        return candidates[fold]
    if fold is not None:
        only_fold = next(key for key, value in candidates.items() if value in unique_instants)
        if fold != only_fold:
            raise InvalidContractValue("temporal_fold is only valid when it selects an actual local-time occurrence")
    return next(iter(unique_instants))


def _midnight_utc(local_date: date, zone: ZoneInfo) -> datetime:
    naive = datetime.combine(local_date, time.min)
    return _localize_strict(naive, zone, None)


@dataclass(frozen=True)
class TemporalResolution:
    temporal_resolution_version: str
    resolution_id: str
    operation_id: str
    timezone: str
    tzdb_version: str
    as_of_at: str
    mode: str
    source: str
    expression_kind: str
    precision: str
    start_at: str | None
    end_at: str | None
    duration_seconds: str | None
    fold: str | None
    requires_clarification: bool
    reason_codes: tuple[str, ...]

    FIELDS: ClassVar[set[str]] = {
        "temporal_resolution_version", "resolution_id", "operation_id", "timezone",
        "tzdb_version", "as_of_at", "mode", "source", "expression_kind", "precision",
        "start_at", "end_at", "duration_seconds", "fold", "requires_clarification",
        "reason_codes",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {key: values[key] for key in TemporalResolution.FIELDS - {"resolution_id"}}

    def __post_init__(self) -> None:
        if self.temporal_resolution_version != TEMPORAL_RESOLUTION_VERSION:
            raise UnsupportedContractVersion("unsupported temporal resolution version")
        _hex64(self.operation_id, "operation_id")
        _nonempty(self.timezone, "timezone", maximum=128)
        _nonempty(self.tzdb_version, "tzdb_version", maximum=128)
        parse_utc_timestamp(self.as_of_at, "as_of_at")
        try:
            mode = TemporalMode(self.mode)
            precision = TemporalPrecision(self.precision)
            TemporalSource(self.source)
        except ValueError as exc:
            raise InvalidContractValue("unsupported temporal mode/source/precision") from exc
        _safe_code(self.expression_kind, "expression_kind")
        if not isinstance(self.requires_clarification, bool):
            raise InvalidContractValue("requires_clarification must be boolean")
        reasons = _reason_codes(self.reason_codes)
        object.__setattr__(self, "reason_codes", reasons)
        if self.fold not in {None, "0", "1"}:
            raise InvalidContractValue("fold must be null, 0, or 1")

        start = parse_utc_timestamp(self.start_at, "start_at") if self.start_at is not None else None
        end = parse_utc_timestamp(self.end_at, "end_at") if self.end_at is not None else None
        if mode in {TemporalMode.INTERVAL, TemporalMode.INSTANT}:
            if start is None or end is None or not start < end:
                raise InvalidContractValue("resolved interval must have start_at < end_at")
            expected_duration = str(int((end - start).total_seconds()))
            if self.duration_seconds is None or canonical_integer(self.duration_seconds, "duration_seconds") != expected_duration:
                raise InvalidContractValue("duration_seconds does not match resolved interval")
            if mode is TemporalMode.INSTANT and (precision is not TemporalPrecision.SECOND or expected_duration != "1"):
                raise InvalidContractValue("instant resolution must be one second at second precision")
        else:
            if any(value is not None for value in (self.start_at, self.end_at, self.duration_seconds, self.fold)):
                raise InvalidContractValue("none/as_of resolution must not carry interval fields")
        if self.requires_clarification and mode is not TemporalMode.NONE:
            raise InvalidContractValue("clarification-required temporal result must not assert an interval")

        source = TemporalSource(self.source)
        if mode is TemporalMode.NONE:
            if precision is not TemporalPrecision.UNSPECIFIED:
                raise InvalidContractValue("none mode must use unspecified precision")
            if self.expression_kind == "none":
                if source is not TemporalSource.NONE or self.requires_clarification or reasons:
                    raise InvalidContractValue("none expression must be unasserted and reason-free")
            elif self.expression_kind == "ambiguous":
                if source is not TemporalSource.QUERY_TEXT or not self.requires_clarification:
                    raise InvalidContractValue("ambiguous temporal result must come from query text and require clarification")
                if reasons != ("temporal_ambiguous",):
                    raise InvalidContractValue("ambiguous temporal result must carry temporal_ambiguous")
            else:
                raise InvalidContractValue("none mode supports only none or ambiguous expression")
        elif mode is TemporalMode.AS_OF:
            if precision is not TemporalPrecision.SECOND or self.expression_kind != "now":
                raise InvalidContractValue("as_of mode must represent now at second precision")
            if source is TemporalSource.NONE or self.requires_clarification or reasons:
                raise InvalidContractValue("as_of mode must have an asserted source and no ambiguity")
        elif mode is TemporalMode.INSTANT:
            if source is TemporalSource.NONE or self.requires_clarification or reasons:
                raise InvalidContractValue("instant mode must have an asserted source and no ambiguity")
            if self.expression_kind not in {"local_instant", "utc_instant"}:
                raise InvalidContractValue("instant mode has an unsupported expression kind")
            if self.expression_kind == "utc_instant" and self.fold is not None:
                raise InvalidContractValue("UTC instant must not carry fold")
        else:
            if source is TemporalSource.NONE or self.requires_clarification or reasons or self.fold is not None:
                raise InvalidContractValue("interval mode must have an asserted source and no ambiguity or fold")
            expected_precision = {
                "today": TemporalPrecision.DAY,
                "yesterday": TemporalPrecision.DAY,
                "tomorrow": TemporalPrecision.DAY,
                "date": TemporalPrecision.DAY,
                "date_range": TemporalPrecision.DAY,
                "this_week": TemporalPrecision.WEEK,
                "last_week": TemporalPrecision.WEEK,
                "next_week": TemporalPrecision.WEEK,
                "this_month": TemporalPrecision.MONTH,
                "last_month": TemporalPrecision.MONTH,
                "next_month": TemporalPrecision.MONTH,
                "month": TemporalPrecision.MONTH,
                "this_year": TemporalPrecision.YEAR,
                "last_year": TemporalPrecision.YEAR,
                "next_year": TemporalPrecision.YEAR,
                "year": TemporalPrecision.YEAR,
                "rolling_7d": TemporalPrecision.ROLLING,
                "rolling_24h": TemporalPrecision.ROLLING,
                "rolling": TemporalPrecision.ROLLING,
            }.get(self.expression_kind)
            if expected_precision is None or precision is not expected_precision:
                raise InvalidContractValue("interval expression kind and precision do not match")

        expected = _identity_hash(self.identity(self.to_mapping()))
        if self.resolution_id != expected:
            raise InvalidContractValue("temporal resolution_id does not match canonical content")

    @classmethod
    def create(cls, **kwargs: object) -> "TemporalResolution":
        values = {"temporal_resolution_version": TEMPORAL_RESOLUTION_VERSION, **kwargs}
        values["reason_codes"] = tuple(sorted(set(values.get("reason_codes", ()))))
        identity = cls.identity({**values, "resolution_id": ""})
        identity["reason_codes"] = list(values["reason_codes"])
        return cls(resolution_id=_identity_hash(identity), **values)  # type: ignore[arg-type]

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "TemporalResolution":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, "temporal resolution")
        values["reason_codes"] = _reason_codes(values["reason_codes"])
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "temporal_resolution_version": self.temporal_resolution_version,
            "resolution_id": self.resolution_id,
            "operation_id": self.operation_id,
            "timezone": self.timezone,
            "tzdb_version": self.tzdb_version,
            "as_of_at": self.as_of_at,
            "mode": self.mode,
            "source": self.source,
            "expression_kind": self.expression_kind,
            "precision": self.precision,
            "start_at": self.start_at,
            "end_at": self.end_at,
            "duration_seconds": self.duration_seconds,
            "fold": self.fold,
            "requires_clarification": self.requires_clarification,
            "reason_codes": list(self.reason_codes),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


_ALIAS_GROUPS: dict[str, tuple[str, ...]] = {
    "now": ("now", "current", "currently", "지금", "현재"),
    "today": ("today", "오늘"),
    "yesterday": ("yesterday", "어제"),
    "tomorrow": ("tomorrow", "내일"),
    "this_week": ("this week", "this_week", "이번 주", "이번주"),
    "last_week": ("last week", "last_week", "지난 주", "지난주"),
    "next_week": ("next week", "next_week", "다음 주", "다음주"),
    "this_month": ("this month", "this_month", "이번 달", "이번달"),
    "last_month": ("last month", "last_month", "지난 달", "지난달"),
    "next_month": ("next month", "next_month", "다음 달", "다음달"),
    "this_year": ("this year", "this_year", "올해"),
    "last_year": ("last year", "last_year", "작년"),
    "next_year": ("next year", "next_year", "내년"),
    "rolling_7d": ("last 7 days", "지난 7일"),
    "rolling_24h": ("last 24 hours", "지난 24시간"),
}
_ALIAS_TO_KIND = {
    re.sub(r"\s+", " ", unicodedata.normalize("NFC", alias).strip().lower()): kind
    for kind, aliases in _ALIAS_GROUPS.items()
    for alias in aliases
}


def _normalized_expression(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFC", value).strip().lower())


def _query_matches(query_text: str | None) -> set[str]:
    if not query_text:
        return set()
    normalized = _normalized_expression(query_text)
    matches: set[str] = set()
    for alias, kind in _ALIAS_TO_KIND.items():
        if re.fullmatch(r"[a-z0-9_ ]+", alias):
            pattern = r"(?<![a-z0-9_])" + re.escape(alias) + r"(?![a-z0-9_])"
            if re.search(pattern, normalized):
                matches.add(kind)
        elif alias in normalized:
            matches.add(kind)
    return matches


class TemporalResolver:
    def __init__(self, timezone_provider: TimezoneProvider | None = None) -> None:
        self.timezone_provider = timezone_provider or SystemTimezoneProvider()

    def _make(
        self,
        *,
        operation_id: str,
        timezone_name: str,
        as_of_at: str,
        mode: TemporalMode,
        source: TemporalSource,
        expression_kind: str,
        precision: TemporalPrecision,
        start: datetime | None = None,
        end: datetime | None = None,
        fold: str | None = None,
        requires_clarification: bool = False,
        reason_codes: tuple[str, ...] = (),
    ) -> TemporalResolution:
        start_at = format_utc_timestamp(start) if start is not None else None
        end_at = format_utc_timestamp(end) if end is not None else None
        duration = str(int((end - start).total_seconds())) if start is not None and end is not None else None
        return TemporalResolution.create(
            operation_id=operation_id,
            timezone=timezone_name,
            tzdb_version=self.timezone_provider.version,
            as_of_at=as_of_at,
            mode=mode.value,
            source=source.value,
            expression_kind=expression_kind,
            precision=precision.value,
            start_at=start_at,
            end_at=end_at,
            duration_seconds=duration,
            fold=fold,
            requires_clarification=requires_clarification,
            reason_codes=reason_codes,
        )

    def resolve(
        self,
        *,
        operation_id: str,
        timezone_name: str,
        as_of_at: str,
        explicit_expression: str | None,
        query_text: str | None,
        temporal_fold: str | None,
    ) -> TemporalResolution:
        _hex64(operation_id, "operation_id")
        zone = self.timezone_provider.get(timezone_name)
        as_of = parse_utc_timestamp(as_of_at, "as_of_at")
        if temporal_fold not in {None, "0", "1"}:
            raise InvalidContractValue("temporal_fold must be null, 0, or 1")

        query_kinds = _query_matches(query_text)
        if explicit_expression is not None:
            expression = _normalized_expression(_nonempty(explicit_expression, "temporal_expression", maximum=256))
            source = TemporalSource.EXPLICIT_FIELD
            explicit_kind = self._kind_for_expression(expression)
            if query_kinds and query_kinds != {explicit_kind}:
                raise InvalidContractValue("explicit temporal expression conflicts with or incompletely resolves query_text")
        else:
            source = TemporalSource.QUERY_TEXT if query_kinds else TemporalSource.NONE
            if len(query_kinds) > 1:
                if temporal_fold is not None:
                    raise InvalidContractValue("temporal_fold cannot be used with an ambiguous query expression")
                return self._make(
                    operation_id=operation_id,
                    timezone_name=timezone_name,
                    as_of_at=as_of_at,
                    mode=TemporalMode.NONE,
                    source=source,
                    expression_kind="ambiguous",
                    precision=TemporalPrecision.UNSPECIFIED,
                    requires_clarification=True,
                    reason_codes=("temporal_ambiguous",),
                )
            if not query_kinds:
                if temporal_fold is not None:
                    raise InvalidContractValue("temporal_fold requires a local timestamp expression")
                return self._make(
                    operation_id=operation_id,
                    timezone_name=timezone_name,
                    as_of_at=as_of_at,
                    mode=TemporalMode.NONE,
                    source=TemporalSource.NONE,
                    expression_kind="none",
                    precision=TemporalPrecision.UNSPECIFIED,
                )
            expression = next(iter(query_kinds))

        try:
            return self._resolve_expression(
                operation_id=operation_id,
                timezone_name=zone.key,
                zone=zone,
                as_of=as_of,
                as_of_at=as_of_at,
                expression=expression,
                source=source,
                temporal_fold=temporal_fold,
            )
        except OverflowError as exc:
            raise InvalidContractValue("temporal expression exceeds supported datetime range") from exc

    @staticmethod
    def _kind_for_expression(expression: str) -> str:
        if expression in _ALIAS_TO_KIND:
            return _ALIAS_TO_KIND[expression]
        if expression in _ALIAS_GROUPS:
            return expression
        if expression.startswith("date:"):
            return "date"
        if expression.startswith("month:"):
            return "month"
        if expression.startswith("year:"):
            return "year"
        if expression.startswith("range:"):
            return "date_range"
        if expression.startswith("local:"):
            return "local_instant"
        if expression.startswith("utc:"):
            return "utc_instant"
        rolling = _ROLLING.fullmatch(expression)
        if rolling:
            amount, unit = rolling.groups()
            if amount == "7" and unit == "d":
                return "rolling_7d"
            if amount == "24" and unit == "h":
                return "rolling_24h"
            return "rolling"
        raise InvalidContractValue("unsupported temporal expression")

    def _resolve_expression(
        self,
        *,
        operation_id: str,
        timezone_name: str,
        zone: ZoneInfo,
        as_of: datetime,
        as_of_at: str,
        expression: str,
        source: TemporalSource,
        temporal_fold: str | None,
    ) -> TemporalResolution:
        kind = self._kind_for_expression(expression)
        if expression in _ALIAS_TO_KIND:
            kind = _ALIAS_TO_KIND[expression]
        if expression in _ALIAS_GROUPS:
            kind = expression
        local_date = as_of.astimezone(zone).date()

        if kind == "now":
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is not valid for now")
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.AS_OF, source=source, expression_kind="now",
                precision=TemporalPrecision.SECOND,
            )

        if kind in {"today", "yesterday", "tomorrow"}:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            offset = {"today": 0, "yesterday": -1, "tomorrow": 1}[kind]
            start_date = local_date + timedelta(days=offset)
            start = _midnight_utc(start_date, zone)
            end = _midnight_utc(start_date + timedelta(days=1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind=kind,
                precision=TemporalPrecision.DAY, start=start, end=end,
            )

        if kind in {"this_week", "last_week", "next_week"}:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            monday = local_date - timedelta(days=local_date.weekday())
            week_offset = {"this_week": 0, "last_week": -1, "next_week": 1}[kind]
            start_date = monday + timedelta(days=7 * week_offset)
            start = _midnight_utc(start_date, zone)
            end = _midnight_utc(start_date + timedelta(days=7), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind=kind,
                precision=TemporalPrecision.WEEK, start=start, end=end,
            )

        if kind in {"this_month", "last_month", "next_month"}:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            year, month = local_date.year, local_date.month
            if kind == "last_month":
                year, month = (year - 1, 12) if month == 1 else (year, month - 1)
            elif kind == "next_month":
                year, month = _next_month(year, month)
            next_year, next_month = _next_month(year, month)
            start = _midnight_utc(date(year, month, 1), zone)
            end = _midnight_utc(date(next_year, next_month, 1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind=kind,
                precision=TemporalPrecision.MONTH, start=start, end=end,
            )

        if kind in {"this_year", "last_year", "next_year"}:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            year = local_date.year + {"this_year": 0, "last_year": -1, "next_year": 1}[kind]
            if not 1 <= year < 9999:
                raise InvalidContractValue("year interval exceeds supported datetime range")
            start = _midnight_utc(date(year, 1, 1), zone)
            end = _midnight_utc(date(year + 1, 1, 1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind=kind,
                precision=TemporalPrecision.YEAR, start=start, end=end,
            )

        if kind in {"rolling_7d", "rolling_24h"}:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            delta = timedelta(days=7) if kind == "rolling_7d" else timedelta(hours=24)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind=kind,
                precision=TemporalPrecision.ROLLING, start=as_of - delta, end=as_of,
            )

        if expression.startswith("date:"):
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            selected = _parse_date(expression[5:], "date expression")
            start = _midnight_utc(selected, zone)
            end = _midnight_utc(selected + timedelta(days=1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind="date",
                precision=TemporalPrecision.DAY, start=start, end=end,
            )

        if expression.startswith("month:"):
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            year, month = _parse_month(expression[6:])
            next_year, next_month = _next_month(year, month)
            start = _midnight_utc(date(year, month, 1), zone)
            end = _midnight_utc(date(next_year, next_month, 1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind="month",
                precision=TemporalPrecision.MONTH, start=start, end=end,
            )

        if expression.startswith("year:"):
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            year = _parse_year(expression[5:])
            if year == 9999:
                raise InvalidContractValue("year interval exceeds supported datetime range")
            start = _midnight_utc(date(year, 1, 1), zone)
            end = _midnight_utc(date(year + 1, 1, 1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind="year",
                precision=TemporalPrecision.YEAR, start=start, end=end,
            )

        if expression.startswith("range:"):
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            body = expression[6:]
            if body.count("/") != 1:
                raise InvalidContractValue("date range must be range:YYYY-MM-DD/YYYY-MM-DD")
            start_text, end_text = body.split("/", 1)
            start_date = _parse_date(start_text, "range start")
            inclusive_end = _parse_date(end_text, "range end")
            if inclusive_end < start_date:
                raise InvalidContractValue("date range end must not precede start")
            start = _midnight_utc(start_date, zone)
            end = _midnight_utc(inclusive_end + timedelta(days=1), zone)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind="date_range",
                precision=TemporalPrecision.DAY, start=start, end=end,
            )

        if expression.startswith("local:"):
            value = expression[6:]
            if not _LOCAL_SECOND.fullmatch(value):
                raise InvalidContractValue("local timestamp must be local:YYYY-MM-DDTHH:MM:SS")
            try:
                naive = datetime.strptime(value.upper(), "%Y-%m-%dT%H:%M:%S")
            except ValueError as exc:
                raise InvalidContractValue("local timestamp is invalid") from exc
            instant = _localize_strict(naive, zone, temporal_fold)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INSTANT, source=source, expression_kind="local_instant",
                precision=TemporalPrecision.SECOND, start=instant, end=instant + timedelta(seconds=1),
                fold=temporal_fold,
            )

        if expression.startswith("utc:"):
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is not valid for UTC instant")
            instant = parse_utc_timestamp(expression[4:].upper().replace("Z", "Z"), "UTC instant")
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INSTANT, source=source, expression_kind="utc_instant",
                precision=TemporalPrecision.SECOND, start=instant, end=instant + timedelta(seconds=1),
            )

        rolling = _ROLLING.fullmatch(expression)
        if rolling:
            if temporal_fold is not None:
                raise InvalidContractValue("temporal_fold is only valid for local instant")
            amount_text, unit = rolling.groups()
            amount = int(canonical_integer(amount_text, "rolling amount"))
            if amount <= 0:
                raise InvalidContractValue("rolling amount must be positive")
            if (unit == "d" and amount > 3650) or (unit == "h" and amount > 87600):
                raise InvalidContractValue("rolling interval exceeds maximum duration")
            delta = timedelta(days=amount) if unit == "d" else timedelta(hours=amount)
            return self._make(
                operation_id=operation_id, timezone_name=timezone_name, as_of_at=as_of_at,
                mode=TemporalMode.INTERVAL, source=source, expression_kind="rolling",
                precision=TemporalPrecision.ROLLING, start=as_of - delta, end=as_of,
            )

        raise InvalidContractValue("unsupported temporal expression")


__all__ = [
    "TEMPORAL_RESOLUTION_VERSION",
    "TemporalMode",
    "TemporalPrecision",
    "TemporalSource",
    "TimezoneProvider",
    "SystemTimezoneProvider",
    "TemporalResolution",
    "TemporalResolver",
]
