"""Adversarial QA / red-team suite for the Gate 1 encrypted-lifecycle
artifact set (docs/adr/ADR-0026, ADR-0027; schemas/encrypted-lifecycle/*;
tests/fixtures/encrypted_lifecycle/*; scripts/*_encrypted_lifecycle_*.py).

This suite is a THIRD, independent surface on top of the two frozen oracles
(generator + validator): it invokes the real CLI scripts as subprocesses,
recomputes crypto/canonicalization primitives from scratch (no shared helper
imports), and actively tries to break the fail-closed contract rather than
merely re-confirm the happy path.

Everything here is read-only with respect to the artifact set under review:
it operates on temp-directory copies for any bundle/tamper scenario, and
regeneration determinism is proven with `diff`, not by leaving a permanent
change behind (the generator is a pure function of fixed test-only IKM, so a
byte-identical in-place re-run leaves the tree unchanged).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PY = sys.executable if "python3.12" in sys.executable else "/usr/local/bin/python3.12"
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle"
SCHEMA_DIR = REPO_ROOT / "schemas" / "encrypted-lifecycle"
ARTIFACTS_DIR = REPO_ROOT / "artifacts" / "encrypted-lifecycle"
SCRIPTS_DIR = REPO_ROOT / "scripts"
ADR_DIR = REPO_ROOT / "docs" / "adr"

GENERATE_SCRIPT = SCRIPTS_DIR / "generate_encrypted_lifecycle_vectors.py"
VALIDATE_SCRIPT = SCRIPTS_DIR / "validate_encrypted_lifecycle_vectors.py"
BUILD_BUNDLE_SCRIPT = SCRIPTS_DIR / "build_encrypted_lifecycle_bundle.py"
IMPORT_BUNDLE_SCRIPT = SCRIPTS_DIR / "import_encrypted_lifecycle_bundle.py"
WRITE_DECISION_SCRIPT = SCRIPTS_DIR / "write_encrypted_lifecycle_gate1_decision.py"

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def run_py(args: list[str], *, cwd: Path = REPO_ROOT, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [PY, *args], cwd=str(cwd), env=env, capture_output=True, text=True, timeout=120
    )


# ---------------------------------------------------------------------------
# Independent (fourth) reimplementation of canonical_bytes and Ed25519 verify,
# deliberately not importing wiki_spike or any script under test.
# ---------------------------------------------------------------------------
def _normalize(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (int, float)):
        raise ValueError(f"raw numeric token forbidden at {path}")
    if isinstance(value, list):
        return [_normalize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise ValueError(f"duplicate key at {path}: {k!r}")
            out[nk] = _normalize(v, f"{path}.{nk}")
        return {k: out[k] for k in sorted(out)}
    raise ValueError(f"unsupported value at {path}: {type(value).__name__}")


def canon(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _normalize(dict(value)), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def rfc6962_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def rfc6962_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return rfc6962_node(rfc6962_root(leaves[:k]), rfc6962_root(leaves[k:]))


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. Two-oracle agreement: run the independent validator as a real subprocess.
# ---------------------------------------------------------------------------
def test_two_oracle_agreement_validator_subprocess_passes():
    result = run_py([str(VALIDATE_SCRIPT)], extra_env={"PYTHONPATH": "src"})
    assert result.returncode == 0, f"validator failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    receipt_path = ARTIFACTS_DIR / "vector-validation-receipt.json"
    assert receipt_path.is_file(), "validator did not write a receipt"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["verdict"] == "PASS"
    assert receipt["checks_run"] >= 100
    assert receipt["failures"] == []


def test_two_oracle_agreement_validator_fails_closed_on_missing_fixtures(tmp_path):
    # Point the validator at an empty fixtures directory by running it from a
    # sandbox copy of the repo layout with fixtures deleted; it must exit
    # non-zero rather than silently reporting success.
    sandbox = tmp_path / "no_fixtures_repo"
    (sandbox / "tests" / "fixtures" / "encrypted_lifecycle").mkdir(parents=True)
    (sandbox / "artifacts" / "encrypted-lifecycle").mkdir(parents=True)
    (sandbox / "scripts").mkdir(parents=True)
    sandbox_script = sandbox / "scripts" / "validate_encrypted_lifecycle_vectors.py"
    sandbox_script.write_text(VALIDATE_SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    # empty fixtures dir (exists but no *.json families) must not fabricate a PASS
    result = run_py([str(sandbox_script)], cwd=sandbox, extra_env={"PYTHONPATH": "src"})
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# 2. Regeneration determinism: the generator is deterministic test-only IKM;
#    a second in-place run must be byte-identical to the committed fixtures.
# ---------------------------------------------------------------------------
def test_regeneration_is_byte_identical_to_committed_fixtures():
    before = {p.name: p.read_bytes() for p in sorted(FIXTURES_DIR.glob("*.json"))}
    assert before, "no committed fixtures found"

    result = run_py([str(GENERATE_SCRIPT)], extra_env={"PYTHONPATH": "src"})
    assert result.returncode == 0, f"generator failed:\nstdout={result.stdout}\nstderr={result.stderr}"

    after = {p.name: p.read_bytes() for p in sorted(FIXTURES_DIR.glob("*.json"))}
    assert set(before) == set(after), "regeneration changed the fixture file set"
    mismatches = [name for name in before if before[name] != after[name]]
    assert mismatches == [], f"non-deterministic regeneration for: {mismatches}"


# ---------------------------------------------------------------------------
# 3. Independence guard: the second oracle must never import the product
#    canonicalizer/crypto module it is supposed to be checking.
# ---------------------------------------------------------------------------
def test_validator_does_not_import_product_canonicalizer():
    source = VALIDATE_SCRIPT.read_text(encoding="utf-8")
    assert "import wiki_spike" not in source
    assert "from wiki_spike" not in source


def test_bundle_importer_does_not_share_module_with_builder():
    builder_source = BUILD_BUNDLE_SCRIPT.read_text(encoding="utf-8")
    importer_source = IMPORT_BUNDLE_SCRIPT.read_text(encoding="utf-8")
    assert "import wiki_spike" not in importer_source
    assert "from wiki_spike" not in importer_source
    # the importer must not import the builder module either (no shared helper)
    assert "import build_encrypted_lifecycle_bundle" not in importer_source
    assert "from build_encrypted_lifecycle_bundle" not in importer_source
    assert builder_source != importer_source


# ---------------------------------------------------------------------------
# 4. Adversarial vector tamper: prove an independent recomputation actually
#    catches a single flipped hex character in history_root, and that an
#    independent Ed25519 verify rejects a mutated attestation signature.
# ---------------------------------------------------------------------------
def test_tampered_history_root_fails_independent_merkle_recomputation():
    data = load_fixture("binding-wire-vectors-v1.json")
    leaf_hashes_hex = data["leaf_hashes_hex"]
    committed_root_hex = data["history_root"]

    leaves = [bytes.fromhex(h) for h in leaf_hashes_hex]
    recomputed_root_hex = rfc6962_root(leaves).hex()
    assert recomputed_root_hex == committed_root_hex, "sanity: recomputation must match the untampered fixture"

    # flip exactly one hex character
    tampered = committed_root_hex[0] + ("1" if committed_root_hex[1] != "1" else "2") + committed_root_hex[2:]
    assert tampered != committed_root_hex
    assert recomputed_root_hex != tampered, "tamper detection failed: mutated root equals independent recomputation"


def test_tampered_attestation_signature_fails_independent_ed25519_verify():
    data = load_fixture("binding-wire-vectors-v1.json")
    attestation = data["attestation"]
    payload = attestation["payload"]
    signature_hex = attestation["signature"]
    signer_key_id = payload["signer_key_id"]
    pub_hex = data["signer_public_keys"][signer_key_id]
    domain = "wiki.binding.latest-read-attestation.v1"

    signing_input = domain.encode("ascii") + b"\x00" + canon(payload)
    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

    # sanity: the untampered signature must verify
    pub_key.verify(bytes.fromhex(signature_hex), signing_input)

    # flip one hex nibble in the signature
    tampered_sig_hex = ("0" if signature_hex[0] != "0" else "1") + signature_hex[1:]
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(tampered_sig_hex), signing_input)


def test_fixture_supplies_its_own_signature_tamper_case_and_it_is_rejected():
    data = load_fixture("binding-wire-vectors-v1.json")
    tamper_cases = {c["case"]: c for c in data["tamper_cases"]}
    sig_case = tamper_cases["signature_flip"]
    assert sig_case["mutated_signature"] != sig_case["original_signature"]

    checkpoint_payload = data["checkpoint"]
    signer_key_id = data["checkpoint_signature"]["key_id"]
    pub_hex = data["signer_public_keys"][signer_key_id]
    domain = "wiki.binding.checkpoint.v1"
    signing_input = domain.encode("ascii") + b"\x00" + canon(checkpoint_payload)
    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

    pub_key.verify(bytes.fromhex(sig_case["original_signature"]), signing_input)
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(sig_case["mutated_signature"]), signing_input)


def test_cross_key_vector_rejects_verification_under_wrong_signer():
    data = load_fixture("binding-wire-vectors-v1.json")
    cross = data["cross_key_vector"]
    domain = cross["domain"]
    signing_input = domain.encode("ascii") + b"\x00" + canon(cross["payload"])
    wrong_pub_hex = data["signer_public_keys"][cross["verify_against_key_id"]]
    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(wrong_pub_hex))
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(cross["signature"]), signing_input)


def test_cross_domain_vector_rejects_verification_under_wrong_domain():
    data = load_fixture("binding-wire-vectors-v1.json")
    cross = data["cross_domain_vector"]
    signer_key_id = cross["signer_key_id"]
    pub_hex = data["signer_public_keys"][signer_key_id]
    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    wrong_signing_input = cross["invalid_domain"].encode("ascii") + b"\x00" + canon(cross["payload"])
    with pytest.raises(InvalidSignature):
        pub_key.verify(bytes.fromhex(cross["signature"]), wrong_signing_input)
    right_signing_input = cross["valid_domain"].encode("ascii") + b"\x00" + canon(cross["payload"])
    pub_key.verify(bytes.fromhex(cross["signature"]), right_signing_input)  # sanity


# ---------------------------------------------------------------------------
# 5. Bundle importer red-team: build a valid bundle, round-trip it clean,
#    then corrupt the manifest bytes several ways and assert REJECTED.
# ---------------------------------------------------------------------------
HEX64_A = "a" * 64
HEX64_B = "b" * 64
HEX64_C = "c" * 64


def _build_clean_bundle(tmp_path: Path) -> tuple[Path, Path, dict]:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "bundle_out"
    input_dir.mkdir()
    payload = input_dir / "feasibility.json"
    payload.write_text(json.dumps({"status": "platform_unavailable", "must_verdict": "PASS"}), encoding="utf-8")

    result = run_py(
        [
            str(BUILD_BUNDLE_SCRIPT),
            "--input", str(input_dir),
            "--output", str(output_dir),
            "--payload", "feasibility.json",
            "--artifact-kind", "SQLCIPHER_FEASIBILITY",
            "--repository", "wiki-spike",
            "--producer-commit", "deadbeef",
            "--contract-digest", HEX64_A,
            "--toolchain-lock-digest", HEX64_B,
            "--workflow-file-digest", HEX64_C,
            "--workflow-run-id", "123",
            "--workflow-run-attempt", "1",
            "--platform", "github-hosted/ubuntu-24.04/x86_64",
        ]
    )
    assert result.returncode == 0, f"bundle build failed:\n{result.stdout}\n{result.stderr}"
    return input_dir, output_dir, {"payload": payload}


def _exploded_bundle_dir(bundle_out: Path, tmp_path: Path, suffix: str) -> Path:
    """Build a directory containing only the loose envelope/manifest/payload
    files (no .tar) so the importer's fallback file-walk path is exercised
    and manifest bytes can be mutated directly."""
    exploded = tmp_path / f"exploded_{suffix}"
    exploded.mkdir()
    (exploded / "bundle-envelope.json").write_bytes((bundle_out / "bundle-envelope.json").read_bytes())
    (exploded / "bundle-manifest.json").write_bytes((bundle_out / "bundle-manifest.json").read_bytes())
    (exploded / "feasibility.json").write_bytes((bundle_out / "feasibility.json").read_bytes() if (bundle_out / "feasibility.json").exists() else (bundle_out.parent / "input" / "feasibility.json").read_bytes())
    return exploded


def test_bundle_round_trip_clean_import_matches_digest(tmp_path):
    input_dir, bundle_out, _ = _build_clean_bundle(tmp_path)
    envelope = json.loads((bundle_out / "bundle-envelope.json").read_text(encoding="utf-8"))
    expected_digest = envelope["bundle_sha256"]
    assert HEX64_RE.match(expected_digest)

    import_out = tmp_path / "imported"
    result = run_py([str(IMPORT_BUNDLE_SCRIPT), "--input", str(bundle_out), "--output", str(import_out)])
    assert result.returncode == 0, f"clean bundle import must succeed:\n{result.stdout}\n{result.stderr}"
    receipt = json.loads((import_out / "import-receipt.json").read_text(encoding="utf-8"))
    assert receipt["verified"] is True
    assert receipt["bundle_sha256"] == expected_digest
    assert receipt["artifact_name"] == envelope["artifact_name"]
    # imported payload bytes must round-trip exactly
    assert (import_out / "feasibility.json").read_bytes() == (input_dir / "feasibility.json").read_bytes()


def _exploded_dir_from_tar(bundle_out: Path, tmp_path: Path, name: str) -> Path:
    exploded = tmp_path / name
    exploded.mkdir()
    tar_path = next(bundle_out.glob("*.tar"))
    with tarfile.open(tar_path, "r") as tar:
        for member in tar.getmembers():
            data = tar.extractfile(member).read()
            (exploded / member.name).write_bytes(data)
    return exploded


@pytest.mark.parametrize(
    "mutate_name",
    ["trailing_whitespace", "reordered_keys", "duplicate_key"],
)
def test_bundle_importer_rejects_noncanonical_manifest_mutations(tmp_path, mutate_name):
    _, bundle_out, _ = _build_clean_bundle(tmp_path)
    exploded = _exploded_dir_from_tar(bundle_out, tmp_path, f"mutate_{mutate_name}")
    manifest_path = exploded / "bundle-manifest.json"
    raw = manifest_path.read_bytes()
    parsed = json.loads(raw.decode("utf-8"))

    if mutate_name == "trailing_whitespace":
        manifest_path.write_bytes(raw + b" ")
    elif mutate_name == "reordered_keys":
        # canonical form sorts keys ("entries" before "schema"); write the
        # semantically-identical object with keys in reverse order.
        reordered = {"schema": parsed["schema"], "entries": parsed["entries"]}
        manifest_path.write_text(json.dumps(reordered, separators=(",", ":")), encoding="utf-8")
    elif mutate_name == "duplicate_key":
        # inject a raw duplicate "schema" key that JSON parsers would collapse
        text = raw.decode("utf-8")
        assert text.startswith('{"entries"')
        injected = text[:1] + f'"schema":{json.dumps(parsed["schema"])},' + text[1:]
        manifest_path.write_text(injected, encoding="utf-8")

    output_dir = tmp_path / f"import_out_{mutate_name}"
    result = run_py([str(IMPORT_BUNDLE_SCRIPT), "--input", str(exploded), "--output", str(output_dir)])
    assert result.returncode != 0, f"importer must reject {mutate_name} mutation"
    assert "REJECTED" in result.stderr
    assert not output_dir.exists(), f"importer must not write output on rejection ({mutate_name})"


def test_bundle_importer_rejects_missing_manifest(tmp_path):
    _, bundle_out, _ = _build_clean_bundle(tmp_path)
    exploded = _exploded_dir_from_tar(bundle_out, tmp_path, "missing_manifest")
    (exploded / "bundle-manifest.json").unlink()

    output_dir = tmp_path / "import_out_missing_manifest"
    result = run_py([str(IMPORT_BUNDLE_SCRIPT), "--input", str(exploded), "--output", str(output_dir)])
    assert result.returncode != 0
    assert "MANIFEST_MISSING" in result.stderr
    assert not output_dir.exists()


def test_bundle_importer_rejects_payload_hash_mismatch(tmp_path):
    _, bundle_out, _ = _build_clean_bundle(tmp_path)
    exploded = _exploded_dir_from_tar(bundle_out, tmp_path, "payload_mismatch")
    (exploded / "feasibility.json").write_text(json.dumps({"status": "ok", "must_verdict": "PASS"}), encoding="utf-8")

    output_dir = tmp_path / "import_out_payload_mismatch"
    result = run_py([str(IMPORT_BUNDLE_SCRIPT), "--input", str(exploded), "--output", str(output_dir)])
    assert result.returncode != 0
    assert "PAYLOAD_HASH_MISMATCH" in result.stderr
    assert not output_dir.exists()


# ---------------------------------------------------------------------------
# 6. Decision fail-closed: REFUSED on a FAIL vector-validation receipt, a
#    missing ADR, and an invalid owner role. Must never write the output.
# ---------------------------------------------------------------------------
def test_decision_refuses_on_failing_vector_validation_receipt(tmp_path):
    fail_receipt = tmp_path / "fail-receipt.json"
    fail_receipt.write_text(json.dumps({"verdict": "FAIL", "checks_run": 5}), encoding="utf-8")
    output_path = tmp_path / "gate1-decision.json"

    result = run_py(
        [
            str(WRITE_DECISION_SCRIPT),
            "--vector-validation", str(fail_receipt),
            "--adr", "docs/adr/ADR-0026-encrypted-lifecycle-authority-identity.md",
            "--adr", "docs/adr/ADR-0027-encrypted-lifecycle-recovery-deletion.md",
            "--schemas-dir", "schemas/encrypted-lifecycle",
            "--owner", "qa-bot:PRODUCT_OWNER",
            "--output", str(output_path),
        ]
    )
    assert result.returncode != 0
    assert "REFUSED" in result.stderr
    assert "VECTOR_VALIDATION_FAILED" in result.stderr
    assert not output_path.exists()


def test_decision_refuses_on_missing_required_adr(tmp_path):
    output_path = tmp_path / "gate1-decision.json"
    result = run_py(
        [
            str(WRITE_DECISION_SCRIPT),
            "--vector-validation", "artifacts/encrypted-lifecycle/vector-validation-receipt.json",
            "--adr", "docs/adr/ADR-9999-does-not-exist.md",
            "--schemas-dir", "schemas/encrypted-lifecycle",
            "--owner", "qa-bot:PRODUCT_OWNER",
            "--output", str(output_path),
        ]
    )
    assert result.returncode != 0
    assert "REFUSED" in result.stderr
    assert "ADR_INPUT_MISSING" in result.stderr
    assert not output_path.exists()


def test_decision_refuses_on_invalid_owner_role(tmp_path):
    output_path = tmp_path / "gate1-decision.json"
    result = run_py(
        [
            str(WRITE_DECISION_SCRIPT),
            "--vector-validation", "artifacts/encrypted-lifecycle/vector-validation-receipt.json",
            "--adr", "docs/adr/ADR-0026-encrypted-lifecycle-authority-identity.md",
            "--schemas-dir", "schemas/encrypted-lifecycle",
            "--owner", "qa-bot:SUPERUSER",
            "--output", str(output_path),
        ]
    )
    assert result.returncode != 0
    assert "REFUSED" in result.stderr
    assert "OWNER_ROLE_INVALID" in result.stderr
    assert not output_path.exists()


def test_decision_refuses_when_no_owners_supplied(tmp_path):
    output_path = tmp_path / "gate1-decision.json"
    result = run_py(
        [
            str(WRITE_DECISION_SCRIPT),
            "--vector-validation", "artifacts/encrypted-lifecycle/vector-validation-receipt.json",
            "--adr", "docs/adr/ADR-0026-encrypted-lifecycle-authority-identity.md",
            "--schemas-dir", "schemas/encrypted-lifecycle",
            "--output", str(output_path),
        ]
    )
    # --owner is `action="append", required=True`; argparse itself refuses
    # (exit 2) rather than the script's own DecisionRefused path, but the
    # fail-closed contract (never write output on any missing input) holds.
    assert result.returncode != 0
    assert not output_path.exists()


# ---------------------------------------------------------------------------
# 7. Schema conformance: validate every embedded object whose declared
#    "schema"/"domain"/"contract_version"/"leaf_type" literal matches a known
#    schema file's const, across every committed fixture; and validate the
#    real Gate 1 decision artifact against its schema.
# ---------------------------------------------------------------------------
def _collect_schema_definitions() -> dict[str, tuple[Path, dict, dict]]:
    """Map every literal const value that appears as the value of a
    schema-identifying property (schema/domain/contract_version) inside any
    schemas/encrypted-lifecycle/*.schema.json file to
    (schema_file_path, enclosing_object_subschema, full_schema_document).
    The enclosing object subschema (not the whole file) is what actually
    describes that const's object shape; the full document is kept as the
    $ref-resolution base."""
    registry: dict[str, tuple[Path, dict, dict]] = {}
    key_names = ("schema", "domain", "contract_version")

    def walk(node: Any, schema_path: Path, schema_doc: dict) -> None:
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                for key in key_names:
                    val = props.get(key)
                    if isinstance(val, dict) and isinstance(val.get("const"), str) and val["const"]:
                        registry.setdefault(val["const"], (schema_path, node, schema_doc))
            for v in node.values():
                walk(v, schema_path, schema_doc)
        elif isinstance(node, list):
            for item in node:
                walk(item, schema_path, schema_doc)

    for schema_file in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema_doc = json.loads(schema_file.read_text(encoding="utf-8"))
        walk(schema_doc, schema_file, schema_doc)
    return registry


SCHEMA_DEFINITION_REGISTRY = _collect_schema_definitions() if jsonschema else {}
def _effective_schema(sub_schema: dict, schema_doc: dict) -> dict:
    """Merge the full document's `definitions` into a copy of `sub_schema` so
    `$ref: "#/definitions/..."` resolves without the deprecated
    jsonschema.RefResolver API."""
    merged = dict(sub_schema)
    merged["definitions"] = schema_doc.get("definitions", {})
    return merged

# Fixture families that embed at least one schema-identified object (and how
# many distinct const-tagged objects each must contain, at minimum).
FIXTURE_MIN_SCHEMA_HITS = {
    "identity-vectors-v1.json": 1,
    "binding-wire-vectors-v1.json": 1,
    "floor-state-vectors-v1.json": 1,
    "bundle-one-pass-vectors-v1.json": 1,
    # pure vector-wrapper families with no dedicated per-object schema file:
    "kdf-vectors-v1.json": 0,
    "nonce-vectors-v1.json": 0,
    "crash-matrix-vectors-v1.json": 0,
    "new-consent-vectors-v1.json": 0,
    "wal-linearization-vectors-v1.json": 0,
}


def _validated_objects(
    node: Any, registry: dict[str, tuple[Path, dict, dict]], path: str = "$"
) -> list[tuple[dict, Path, dict, dict, str]]:
    found: list[tuple[dict, Path, dict, dict, str]] = []
    if isinstance(node, dict):
        for key in ("schema", "domain", "contract_version"):
            val = node.get(key)
            if isinstance(val, str) and val in registry:
                schema_path, sub_schema, schema_doc = registry[val]
                found.append((node, schema_path, sub_schema, schema_doc, path))
                break
        for k, v in node.items():
            found.extend(_validated_objects(v, registry, f"{path}.{k}"))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found.extend(_validated_objects(item, registry, f"{path}[{i}]"))
    return found


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
@pytest.mark.parametrize("fixture_name", sorted(FIXTURE_MIN_SCHEMA_HITS))
def test_fixture_embedded_objects_conform_to_matching_schemas(fixture_name):
    assert SCHEMA_DEFINITION_REGISTRY, "schema definition registry must not be empty"
    assert set(FIXTURE_MIN_SCHEMA_HITS) == {p.name for p in FIXTURES_DIR.glob("*.json")}, (
        "FIXTURE_MIN_SCHEMA_HITS drifted from the committed fixture file set"
    )
    data = load_fixture(fixture_name)
    candidates = _validated_objects(data, SCHEMA_DEFINITION_REGISTRY)
    # deliberately-invalid fixture entries (used elsewhere to prove a schema
    # REJECTS them) are excluded from this "must conform" pass; they are
    # covered by the freshness-gate invariant tests below instead.
    candidates = [c for c in candidates if "invalid_in_enum_pairs" not in c[4]]
    checked = 0
    for obj, schema_path, sub_schema, schema_doc, path in candidates:
        effective_schema = _effective_schema(sub_schema, schema_doc)
        jsonschema.validate(instance=obj, schema=effective_schema)
        checked += 1
    assert checked >= FIXTURE_MIN_SCHEMA_HITS[fixture_name], (
        f"{fixture_name}: expected >={FIXTURE_MIN_SCHEMA_HITS[fixture_name]} schema-identified "
        f"objects, found {checked}"
    )


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_floor_state_fixture_invalid_freshness_pairs_are_rejected_by_schema():
    data = load_fixture("floor-state-vectors-v1.json")
    invalid_cases = data["freshness_serve_gate"]["invalid_in_enum_pairs"]
    assert len(invalid_cases) == 3
    for case in invalid_cases:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=case["gate"], schema=FRESHNESS_SCHEMA)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_floor_state_fixture_valid_freshness_pairs_are_accepted_by_schema():
    data = load_fixture("floor-state-vectors-v1.json")
    valid_cases = data["freshness_serve_gate"]["valid_pairs"]
    assert len(valid_cases) == 3
    for case in valid_cases:
        jsonschema.validate(instance=case, schema=FRESHNESS_SCHEMA)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_fixture_schema_conformance_rejects_a_broken_object():
    schema_path, sub_schema, schema_doc = SCHEMA_DEFINITION_REGISTRY["wiki-binding-latest-read-attestation-v1"]
    data = load_fixture("binding-wire-vectors-v1.json")
    payload = copy.deepcopy(data["attestation"]["payload"])
    effective_schema = _effective_schema(sub_schema, schema_doc)
    jsonschema.validate(instance=payload, schema=effective_schema)  # sanity: clean payload passes

    del payload["history_root"]  # required field removed
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=effective_schema)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_gate1_decision_artifact_conforms_to_its_schema():
    decision_path = ARTIFACTS_DIR / "gate1-decision.json"
    assert decision_path.is_file(), "expected artifacts/encrypted-lifecycle/gate1-decision.json to exist"
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    schema_doc = json.loads((SCHEMA_DIR / "gate1-decision-v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(instance=decision, schema=schema_doc)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
def test_gate1_decision_schema_rejects_unknown_profile_selection():
    decision_path = ARTIFACTS_DIR / "gate1-decision.json"
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    schema_doc = json.loads((SCHEMA_DIR / "gate1-decision-v1.schema.json").read_text(encoding="utf-8"))
    broken = copy.deepcopy(decision)
    broken["profile_selection"] = "C"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=broken, schema=schema_doc)


# ---------------------------------------------------------------------------
# 8. Freshness-gate invariant: exactly three legal (state,reason) pairs are
#    admitted; every other combination of the enum values is rejected.
# ---------------------------------------------------------------------------
FRESHNESS_SCHEMA = json.loads((SCHEMA_DIR / "freshness-serve-gate-v1.schema.json").read_text(encoding="utf-8"))
FRESHNESS_STATES = ["CLEAR", "FRESH_CHALLENGE_REQUIRED"]
FRESHNESS_REASONS = ["NONE", "ATTESTATION_EXPIRED_BEFORE_STABILIZE", "CLOCK_WINDOW_EXPIRED"]
FRESHNESS_VALID_PAIRS = {
    ("CLEAR", "NONE"),
    ("FRESH_CHALLENGE_REQUIRED", "ATTESTATION_EXPIRED_BEFORE_STABILIZE"),
    ("FRESH_CHALLENGE_REQUIRED", "CLOCK_WINDOW_EXPIRED"),
}


def _freshness_instance(state: str, reason: str) -> dict:
    return {
        "schema": "wiki-freshness-serve-gate-v1",
        "workspace_id": "ws-test-1",
        "state": state,
        "stable_floor_generation": "1",
        "stable_checkpoint_id": "a" * 64,
        "source_candidate_digest": "b" * 64,
        "reason": reason,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
@pytest.mark.parametrize("state,reason", sorted(FRESHNESS_VALID_PAIRS))
def test_freshness_gate_accepts_exactly_the_three_valid_pairs(state, reason):
    jsonschema.validate(instance=_freshness_instance(state, reason), schema=FRESHNESS_SCHEMA)


@pytest.mark.skipif(jsonschema is None, reason="jsonschema not installed")
@pytest.mark.parametrize(
    "state,reason",
    sorted(
        (s, r)
        for s in FRESHNESS_STATES
        for r in FRESHNESS_REASONS
        if (s, r) not in FRESHNESS_VALID_PAIRS
    ),
)
def test_freshness_gate_rejects_all_invalid_state_reason_pairs(state, reason):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=_freshness_instance(state, reason), schema=FRESHNESS_SCHEMA)


def test_freshness_gate_invalid_pair_count_is_exactly_three():
    all_pairs = {(s, r) for s in FRESHNESS_STATES for r in FRESHNESS_REASONS}
    invalid_pairs = all_pairs - FRESHNESS_VALID_PAIRS
    assert len(FRESHNESS_VALID_PAIRS) == 3
    assert len(invalid_pairs) == 3
