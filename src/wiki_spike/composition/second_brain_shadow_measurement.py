"""Closed local composition for native shadow measurement; no serving dependencies."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from wiki_spike.canonical import CanonicalizationError, canonical_bytes

from wiki_spike.applications.second_brain_shadow_measurement import (
    AuthoritySnapshot,
    MonotonicAppendAuthority,
    NativeShadowMeasurementCollector,
    ShadowMeasurementError,
)
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BenchmarkManifestV1,
    HoldoutManifestV1,
    NATIVE_SHADOW_SOURCES,
    RecallSloV1,
)


class ShadowMeasurementCompositionError(ValueError):
    """Local measurement inputs are incomplete or do not bind one cohort."""


def _load_object(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShadowMeasurementCompositionError("manifest must be a readable JSON object") from exc
    if not isinstance(value, dict):
        raise ShadowMeasurementCompositionError("manifest must be a JSON object")
    return value


def _bound_manifest_digest(value: Mapping[str, Any], field: str) -> str:
    digest = _manifest_digest(value, field)
    body = dict(value)
    del body[field]
    try:
        actual = sha256(canonical_bytes(body)).hexdigest()
    except CanonicalizationError as exc:
        raise ShadowMeasurementCompositionError(f"{field} body is not canonical") from exc
    if actual != digest:
        raise ShadowMeasurementCompositionError(f"{field} does not bind manifest body")
    return digest


def _manifest_digest(value: Mapping[str, Any], field: str) -> str:
    digest = value.get(field)
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ShadowMeasurementCompositionError(f"manifest lacks {field}")
    return digest
_SOURCE_MANIFEST_FIELDS = {
    "manifest_version", "workspace_ref", "profiles", "source_manifest_digest",
}
_CAPABILITY_MANIFEST_FIELDS = {
    "manifest_version", "workspace_ref", "benchmark_key_ref", "holdout_key_ref",
    "benchmark_capability_ref", "holdout_capability_ref", "capabilities",
    "denied_capabilities", "capability_manifest_digest",
}
_NATIVE_MEASUREMENT_CAPABILITIES = ("local-authenticated-measurement",)
_DENIED_MEASUREMENT_CAPABILITIES = (
    "serving", "activation", "promotion", "routes", "export", "network",
)


def _strict_manifest(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    unknown, missing = set(value) - fields, fields - set(value)
    if unknown or missing:
        raise ShadowMeasurementCompositionError(
            f"{label} manifest fields invalid unknown={sorted(unknown)} missing={sorted(missing)}"
        )


def _exact_strings(value: Any, expected: tuple[str, ...], field: str) -> None:
    if not isinstance(value, list) or tuple(value) != expected:
        raise ShadowMeasurementCompositionError(f"{field} must exactly equal the native measurement roster")


def _manifest_ref(value: Any, expected: str, field: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise ShadowMeasurementCompositionError(f"{field} does not bind the measurement cohort")


def _validate_source_manifest(value: Mapping[str, Any], workspace_ref: str) -> None:
    _strict_manifest(value, _SOURCE_MANIFEST_FIELDS, "source")
    if value.get("manifest_version") != "native-source-manifest-v1":
        raise ShadowMeasurementCompositionError("unsupported source manifest version")
    _exact_strings(value.get("profiles"), NATIVE_SHADOW_SOURCES, "source profiles")
    _manifest_ref(value.get("workspace_ref"), workspace_ref, "source workspace_ref")


def _validate_capability_manifest(
    value: Mapping[str, Any], benchmark: BenchmarkManifestV1, holdout: HoldoutManifestV1,
) -> None:
    _strict_manifest(value, _CAPABILITY_MANIFEST_FIELDS, "capability")
    if value.get("manifest_version") != "native-capability-manifest-v1":
        raise ShadowMeasurementCompositionError("unsupported capability manifest version")
    _exact_strings(value.get("capabilities"), _NATIVE_MEASUREMENT_CAPABILITIES, "capabilities")
    _exact_strings(value.get("denied_capabilities"), _DENIED_MEASUREMENT_CAPABILITIES, "denied capabilities")
    _manifest_ref(value.get("workspace_ref"), benchmark.workspace_ref, "capability workspace_ref")
    _manifest_ref(value.get("benchmark_key_ref"), benchmark.corpus_key_ref, "benchmark_key_ref")
    _manifest_ref(value.get("holdout_key_ref"), holdout.holdout_key_ref, "holdout_key_ref")
    _manifest_ref(value.get("benchmark_capability_ref"), benchmark.capability_ref, "benchmark_capability_ref")
    _manifest_ref(value.get("holdout_capability_ref"), holdout.capability_ref, "holdout_capability_ref")


def _trusted_key(path: str | Path, fingerprint: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
        key = Ed25519PublicKey.from_public_bytes(raw)
    except (OSError, ValueError) as exc:
        raise ShadowMeasurementCompositionError("measurement public key must be a raw Ed25519 hex file") from exc
    actual = sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
    if actual != fingerprint:
        raise ShadowMeasurementCompositionError("measurement public key fingerprint does not match")
    return key


def open_measurement(
    *, db: str | Path, authority: MonotonicAppendAuthority,
    measurement_public_key: str | Path, measurement_key_fingerprint: str,
    resolved_scope: str | Path, contract: str | Path, source_manifest: str | Path,
    capability_manifest: str | Path, benchmark_manifest: str | Path, holdout_manifest: str | Path,
    checkpoint: str | Path | None = None, create: bool = False,
) -> NativeShadowMeasurementCollector:
    """Open a cohort only when every supplied local manifest binds the same roots."""
    db_path = Path(db)
    segments_path = db_path.with_suffix(db_path.suffix + ".segments")
    if create:
        if db_path.exists() or segments_path.exists():
            raise ShadowMeasurementCompositionError("init requires a fresh measurement DB")
        if checkpoint is None:
            raise ShadowMeasurementCompositionError("init requires a signed cohort checkpoint")
    elif not segments_path.is_dir():
        raise ShadowMeasurementCompositionError("measurement DB is missing")
    scope_data = _load_object(resolved_scope)
    source_data = _load_object(source_manifest)
    capability_data = _load_object(capability_manifest)
    try:
        scope = ResolvedScopeV1.from_mapping(scope_data)
        benchmark = BenchmarkManifestV1.from_mapping(_load_object(benchmark_manifest))
        holdout = HoldoutManifestV1.from_mapping(_load_object(holdout_manifest))
        slo = RecallSloV1.from_mapping(_load_object(contract))
    except Exception as exc:
        raise ShadowMeasurementCompositionError("resolved scope, contract, benchmark, or holdout manifest is invalid") from exc
    if _bound_manifest_digest(source_data, "source_manifest_digest") != scope.source_manifest_digest:
        raise ShadowMeasurementCompositionError("source manifest does not bind resolved scope")
    if _bound_manifest_digest(capability_data, "capability_manifest_digest") != scope.capability_manifest_digest:
        raise ShadowMeasurementCompositionError("capability manifest does not bind resolved scope")
    if benchmark.workspace_ref != holdout.workspace_ref:
        raise ShadowMeasurementCompositionError("benchmark and holdout must use the same workspace")
    if benchmark.corpus_key_ref == holdout.holdout_key_ref:
        raise ShadowMeasurementCompositionError("benchmark and holdout keys must be separate")
    if benchmark.capability_ref == holdout.capability_ref:
        raise ShadowMeasurementCompositionError("benchmark and holdout capabilities must be separate")
    _validate_source_manifest(source_data, benchmark.workspace_ref)
    _validate_capability_manifest(capability_data, benchmark, holdout)
    key = _trusted_key(measurement_public_key, measurement_key_fingerprint)
    try:
        if not all(isinstance(value, str) and value for value in (
            authority.identity, authority.endpoint, authority.policy_id,
        )):
            raise ValueError("authority identity metadata missing")
        authority.public_key
    except Exception as exc:
        raise ShadowMeasurementCompositionError("an external authenticated monotonic authority adapter is required") from exc
    collector = NativeShadowMeasurementCollector(
        path=db_path, authority=authority, scope=scope, benchmark=benchmark, holdout=holdout, slo=slo,
        measurement_public_key=key, measurement_key_id=measurement_key_fingerprint,
    )
    if create:
        checkpoint_data = _load_object(checkpoint)
        if set(checkpoint_data) != {"cohort_id", "started_at", "anchor_root", "root_signature"}:
            raise ShadowMeasurementCompositionError("cohort checkpoint schema is invalid")
        try:
            collector.establish_checkpoint(**checkpoint_data)
        except ShadowMeasurementError as exc:
            raise ShadowMeasurementCompositionError("cohort checkpoint is invalid") from exc
    return collector


def report_measurement(collector: NativeShadowMeasurementCollector) -> dict[str, Any]:
    """Revalidate durable evidence and return its non-serving outcome."""
    report = collector.report()
    return {
        "outcome": report.outcome,
        "cohort_digest": report.cohort_digest,
        "sample_count": report.sample_count,
        "continuous_seconds": report.continuous_seconds,
        "reasons": list(report.reasons),
    }


__all__ = ["ShadowMeasurementCompositionError", "open_measurement", "report_measurement"]
