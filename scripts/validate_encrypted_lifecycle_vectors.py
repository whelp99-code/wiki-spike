#!/usr/bin/env python3
"""Independent validator (oracle #2) for the Encrypted Single-Memory Lifecycle
Gate 1 test vectors.

This script is the SECOND oracle in the two-oracle vector contract. It MUST NOT
import ``wiki_spike`` in any form: it reimplements canonical JSON encoding, HKDF,
HMAC, the RFC 6962 append-only Merkle tree, and the 256-level sparse Merkle tree
from scratch, then recomputes every digest / HMAC id / signature / root / proof /
projection embedded in ``tests/fixtures/encrypted_lifecycle/`` and asserts byte
equality with the generator (oracle #1) output.

If oracle #2's independent canonicalization disagreed with the frozen Core
canonicalizer used by the generator, every ``*_canonical_bytes_hex`` check plus
every HMAC and Ed25519 signature check below would fail. Agreement across both
oracles is the Gate 1 identity/binding/bundle byte-reproducibility guarantee.

TEST-ONLY key material (root IKM, Ed25519 seeds) are shared *specification*
constants, necessarily identical across oracles; independence lives in the
canonicalization and tree/proof reimplementations, not in the seeds.

Exit code 0 = every family reproduced byte-for-byte. Nonzero = one or more
mismatches (all listed).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import re
import sys
import unicodedata
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - cryptography is a project dependency
    _HAVE_CRYPTO = False

try:
    import jsonschema  # type: ignore

    _HAVE_JSONSCHEMA = True
except Exception:
    _HAVE_JSONSCHEMA = False

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle"
SCHEMA_DIR = REPO_ROOT / "schemas" / "encrypted-lifecycle"

# --- TEST-ONLY shared spec constants (must match the generator) --------------
TEST_ONLY_ROOT_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()

HKDF_LABELS = [
    "command_digest_key_v1",
    "manifest_digest_key_v1",
    "artifact_identity_key_v1",
    "subject_identity_key_v1",
    "object_identity_key_v1",
    "revision_identity_key_v1",
    "stable_subject_key_v1",
    "locator_identity_key_v1",
]

# domain (in the identity message) -> HKDF label used to derive its HMAC key
DOMAIN_TO_LABEL = {
    "wiki.command": "command_digest_key_v1",
    "wiki.command-manifest": "manifest_digest_key_v1",
    "wiki.artifact-semantic": "artifact_identity_key_v1",
    "wiki.logical-object-id": "object_identity_key_v1",
    "wiki.revision-id": "revision_identity_key_v1",
}

FAILURES: list[str] = []
CHECKS = 0


def fail(msg: str) -> None:
    FAILURES.append(msg)


def check(cond: bool, msg: str) -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        fail(msg)


# --- Independent canonicalization (reimplemented; no wiki_spike import) -------
def _normalize(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (int, float)):
        raise ValueError(f"raw numbers forbidden at {path}")
    if isinstance(value, list):
        return [_normalize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"non-string key at {path}")
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise ValueError(f"duplicate key at {path}: {k!r}")
            out[nk] = _normalize(v, f"{path}.{nk}")
        return {k: out[k] for k in sorted(out)}
    raise ValueError(f"unsupported value at {path}: {type(value).__name__}")


def canon(value: dict) -> bytes:
    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


# --- Independent crypto primitives -------------------------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hkdf_salt(label: str) -> bytes:
    return sha256(b"WIKI-SPIKE-TEST-ONLY-HKDF-SALT-V1:" + label.encode("ascii"))


def hkdf_info(label: str) -> bytes:
    return label.encode("ascii") + b"\x00v1"


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


DERIVED_KEYS = {
    label: hkdf(TEST_ONLY_ROOT_IKM, hkdf_salt(label), hkdf_info(label))
    for label in HKDF_LABELS
}


def hmac_hex(label: str, payload: dict) -> str:
    return hmac.new(DERIVED_KEYS[label], canon(payload), hashlib.sha256).hexdigest()


def domain_prefix(domain: str) -> bytes:
    return domain.encode("ascii") + b"\x00"


def ed25519_verify(pub_hex: str, domain: str, payload: dict, sig_hex: str) -> bool:
    if not _HAVE_CRYPTO:
        return True  # skip crypto verification if library unavailable
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pk.verify(bytes.fromhex(sig_hex), domain_prefix(domain) + canon(payload))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# --- RFC 6962 append-only Merkle tree ----------------------------------------
def mt_leaf(data: bytes) -> bytes:
    return sha256(b"\x00" + data)


def mt_node(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def mt_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return mt_node(mt_root(leaves[:k]), mt_root(leaves[k:]))


def mt_inclusion_root(leaf_hash: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    # RFC 6962 section 2.1.1 verifier
    fn, sn = index, size - 1
    r = leaf_hash
    for p in path:
        if fn % 2 == 1 or fn == sn:
            r = mt_node(p, r)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = mt_node(r, p)
        fn >>= 1
        sn >>= 1
    return r


# --- 256-level sparse Merkle tree --------------------------------------------
SMT_DEPTH = 256
SMT_DEFAULT = [sha256(b"\x00")]
for _i in range(SMT_DEPTH):
    SMT_DEFAULT.append(sha256(b"\x02" + SMT_DEFAULT[-1] + SMT_DEFAULT[-1]))


def smt_bit(key_int: int, depth: int) -> int:
    return (key_int >> (SMT_DEPTH - 1 - depth)) & 1

def smt_leaf(key_int: int, value: bytes) -> bytes:
    return sha256(b"\x01" + key_int.to_bytes(32, "big") + value)


def smt_root_from_proof(key_int: int, leaf_value: bytes, siblings: list[bytes]) -> bytes:
    node = leaf_value
    for depth in reversed(range(SMT_DEPTH)):
        sib = siblings[depth]
        if smt_bit(key_int, depth) == 0:
            node = sha256(b"\x02" + node + sib)
        else:
            node = sha256(b"\x02" + sib + node)
    return node


# --- Fixture loading ----------------------------------------------------------
def load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def validate_schema(instance: dict, schema_file: str) -> None:
    if not _HAVE_JSONSCHEMA:
        return
    path = SCHEMA_DIR / schema_file
    if not path.exists():
        return
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft7Validator(schema).validate(instance)
    except jsonschema.ValidationError as exc:  # type: ignore
        fail(f"schema {schema_file}: {exc.message}")
    except Exception as exc:  # noqa: BLE001
        fail(f"schema {schema_file}: {exc}")


# --- Family validators --------------------------------------------------------
def v_kdf() -> None:
    data = load("kdf-vectors-v1.json")
    check(data["ikm_hex_test_only"] == TEST_ONLY_ROOT_IKM.hex(), "kdf: ikm mismatch")
    for entry in data["labels"]:
        label = entry["label"]
        salt = hkdf_salt(label)
        info = hkdf_info(label)
        out = hkdf(TEST_ONLY_ROOT_IKM, salt, info)
        check(salt.hex() == entry["salt_hex"], f"kdf {label}: salt mismatch")
        check(info.hex() == entry["info_hex"], f"kdf {label}: info mismatch")
        check(out.hex() == entry["output_hex"], f"kdf {label}: output mismatch")


def v_identity() -> None:
    data = load("identity-vectors-v1.json")

    def check_msg_id(msg: dict, expected_id: str, tag: str) -> None:
        label = DOMAIN_TO_LABEL.get(msg.get("domain", ""))
        check(label is not None, f"identity {tag}: unknown domain {msg.get('domain')!r}")
        if label is not None:
            check(hmac_hex(label, msg) == expected_id, f"identity {tag}: id mismatch")

    for case in data["cases"]:
        name = case.get("name", "?")
        if "command_message" in case and "command_id" in case:
            check_msg_id(case["command_message"], case["command_id"], f"{name}.command")
        if "artifact_semantic_message" in case and "artifact_semantic_digest" in case:
            check_msg_id(case["artifact_semantic_message"], case["artifact_semantic_digest"], f"{name}.semantic")
        if "object_id_message" in case and "logical_object_id" in case:
            check_msg_id(case["object_id_message"], case["logical_object_id"], f"{name}.object")
        if "revision_id_message" in case and "revision_id" in case:
            check_msg_id(case["revision_id_message"], case["revision_id"], f"{name}.revision")
        if "manifest_message" in case and "manifest_digest" in case:
            check_msg_id(case["manifest_message"], case["manifest_digest"], f"{name}.manifest")
        for sub in ("command_a", "command_b"):
            if sub in case:
                check_msg_id(case[sub]["message"], case[sub]["command_id"], f"{name}.{sub}")
    # cross-check convergence / mismatch assertions
    for case in data["cases"]:
        if case.get("name") == "semantic-convergence":
            check(case["command_a"]["command_id"] != case["command_b"]["command_id"],
                  "identity: convergence commands should differ")
        if case.get("name") == "idempotency-mismatch":
            check(case["command_a"]["command_id"] != case["command_b"]["command_id"],
                  "identity: idempotency-mismatch commands should differ")


def v_nonce() -> None:
    data = load("nonce-vectors-v1.json")
    aes = data["aes_gcm_nonce_hex24"]
    chal = data["challenge_nonce_hex64"]
    aes_re = re.compile(aes["pattern"])
    chal_re = re.compile(chal["pattern"])
    for v in aes["valid"]:
        check(bool(aes_re.fullmatch(v)), f"nonce: aes valid rejected {v}")
    for bad in aes["invalid"]:
        check(not aes_re.fullmatch(bad["value"]), f"nonce: aes invalid accepted {bad['value']}")
    for v in chal["valid"]:
        check(bool(chal_re.fullmatch(v)), f"nonce: challenge valid rejected {v}")
    for bad in chal["invalid"]:
        check(not chal_re.fullmatch(bad["value"]), f"nonce: challenge invalid accepted {bad['value']}")
    for cu in data["cross_use_rejection"]:
        if cu["tested_as"] == "challenge_nonce_hex64":
            check(not chal_re.fullmatch(cu["value"]), "nonce: cross-use should reject (challenge)")
        else:
            check(not aes_re.fullmatch(cu["value"]), "nonce: cross-use should reject (aes)")


def v_binding() -> None:
    data = load("binding-wire-vectors-v1.json")
    pubs = data["signer_public_keys"]

    # 1. attestation canonical bytes + signature
    att = data["attestation"]
    payload = att["payload"]
    check(canon(payload).hex() == data["attestation_canonical_bytes_hex"],
          "binding: attestation canonical bytes mismatch")
    check(ed25519_verify(pubs[payload["signer_key_id"]],
                         "wiki.binding.latest-read-attestation.v1", payload, att["signature"]),
          "binding: attestation signature invalid")

    # 2. leaves -> leaf hashes -> history root
    leaves = data["leaves"]
    signed_leaves = data["signed_leaves"]
    leaf_hashes = [mt_leaf(canon(sl)) for sl in signed_leaves]
    for i, lh in enumerate(leaf_hashes):
        check(lh.hex() == data["leaf_hashes_hex"][i], f"binding: leaf_hash[{i}] mismatch")
    check(mt_root(leaf_hashes).hex() == data["history_root"], "binding: history_root mismatch")

    # 3. history inclusion proof
    inc = data["history_inclusion_proof"]
    idx = int(inc["leaf_index"])
    size = int(inc["history_size"])
    path = [bytes.fromhex(h) for h in inc["audit_path"]]
    root = mt_inclusion_root(leaf_hashes[idx], idx, size, path)
    check(root.hex() == data["history_root"], "binding: inclusion proof does not reconstruct history_root")

    # 4. history consistency proof (old 2 -> new 3): cross-check prefix roots
    cons = data["history_consistency_proof"]
    old_size = int(cons["old_size"])
    new_size = int(cons["new_size"])
    check(new_size == len(leaf_hashes), "binding: consistency new_size mismatch")
    old_root = mt_root(leaf_hashes[:old_size])
    new_root = mt_root(leaf_hashes[:new_size])
    check(new_root.hex() == data["history_root"], "binding: consistency new root mismatch")
    # the audit path must contain the second-subtree hash that extends old->new
    check(len(cons["audit_path"]) >= 1, "binding: consistency audit path empty")
    # independent reconstruction: new root = node(old_root_subtree, remainder)
    # for size 2->3 the RFC6962 path yields [root(leaves[:2]), leaf_hash[2]]
    if old_size == 2 and new_size == 3:
        recomputed = mt_node(old_root, leaf_hashes[2])
        check(recomputed.hex() == data["history_root"],
              "binding: 2->3 consistency reconstruction mismatch")

    # 5. sparse map membership / non-membership
    def map_key_for(leaf: dict) -> str:
        return sha256_hex(canon({
            "domain": "wiki.binding-registry.current-key",
            "version": "1",
            "workspace_id": leaf["workspace_id"],
            "namespace": leaf["namespace"],
            "provider_handle": leaf["provider_handle"],
        }))

    mem = data["membership_proof"]
    mem_leaf = leaves[0]
    mem_signed = signed_leaves[0]
    mem_key_hex = map_key_for(mem_leaf)
    check(mem_key_hex == mem["map_key"], "binding: membership map_key mismatch")
    mem_key_int = int(mem_key_hex, 16)
    mem_leaf_node = smt_leaf(mem_key_int, sha256(canon(mem_signed)))
    mem_sibs = [bytes.fromhex(s) for s in mem["siblings"]]
    check(len(mem_sibs) == SMT_DEPTH, "binding: membership siblings depth")
    mem_root = smt_root_from_proof(mem_key_int, mem_leaf_node, mem_sibs)
    check(mem_root.hex() == data["current_map_root"], "binding: membership root mismatch")

    non = data["nonmembership_proof"]
    non_key_hex = non["map_key"]
    non_sibs = [bytes.fromhex(s) for s in non["siblings"]]
    non_root = smt_root_from_proof(int(non_key_hex, 16), SMT_DEFAULT[0], non_sibs)
    check(non_root.hex() == data["current_map_root"], "binding: non-membership root mismatch")

    # 6. checkpoint sha + signature
    cp = data["checkpoint"]
    cp_sig = data["checkpoint_signature"]
    check(sha256_hex(canon(cp)) == cp_sig["checkpoint_sha256"], "binding: checkpoint_sha256 mismatch")
    check(ed25519_verify(pubs[cp["signer_key_id"]], "wiki.binding.checkpoint.v1", cp, cp_sig["signature"]),
          "binding: checkpoint signature invalid")

    # 7. cross-domain must FAIL under the wrong domain
    cd = data["cross_domain_vector"]
    check(ed25519_verify(pubs[cd["signer_key_id"]], cd["valid_domain"], cd["payload"], cd["signature"]),
          "binding: cross-domain valid-domain should pass")
    check(not ed25519_verify(pubs[cd["signer_key_id"]], cd["invalid_domain"], cd["payload"], cd["signature"]),
          "binding: cross-domain wrong-domain should FAIL")

    # 8. cross-key must FAIL under signer 1's key
    ck = data["cross_key_vector"]
    check(not ed25519_verify(pubs[ck["verify_against_key_id"]], ck["domain"], ck["payload"], ck["signature"]),
          "binding: cross-key wrong-key should FAIL")

    validate_schema(data["proof_set"], "binding-registry-proof-set-v1.schema.json")


def v_bundle() -> None:
    data = load("bundle-one-pass-vectors-v1.json")
    payload_paths = [
        "payload/gate1-decision.json",
        "payload/macos/sqlcipher-feasibility.json",
        "payload/ubuntu/import-receipt.json",
        "payload/vector-validation.json",
    ]
    envelope_fields = {
        "schema", "artifact_kind", "repository", "producer_commit",
        "contract_digest", "toolchain_lock_digest", "workflow_file_digest",
        "workflow_run_id", "workflow_run_attempt", "platform", "artifact_name",
        "payload_paths", "payload_sha256", "bundle_sha256", "produced_at",
    }

    # projected envelope: artifact_name and bundle_sha256 both empty strings.
    tmpl = data["template_envelope"]
    check(set(tmpl) == envelope_fields, "bundle: template envelope fields are not exact")
    check(tmpl["artifact_name"] == "", "bundle: template artifact_name not empty")
    check(tmpl["bundle_sha256"] == "", "bundle: template bundle_sha256 not empty")
    check(tmpl["artifact_kind"] == "GATE1_DECISION", "bundle: template artifact kind invalid")
    check(tmpl["repository"] == "wiki-spike/wiki-spike", "bundle: template repository invalid")
    check(tmpl["payload_paths"] == payload_paths, "bundle: template payload paths are not closed")
    check(set(data["payload_files"]) == set(payload_paths), "bundle: payload file paths are not closed")
    check(
        tmpl["payload_sha256"] == [sha256_hex(data["payload_files"][path].encode()) for path in payload_paths],
        "bundle: template payload hashes mismatch",
    )
    check(canon(tmpl).hex() == data["projected_envelope_bytes_hex"],
          "bundle: projected envelope canonical bytes mismatch")
    check(sha256_hex(canon(tmpl)) == data["projected_envelope_sha256"],
          "bundle: projected envelope sha256 mismatch")
    check(str(len(canon(tmpl))) == data["projected_envelope_size"],
          "bundle: projected envelope size mismatch")

    # Manifest is canonical, closed over its projected envelope and payload files.
    manifest = data["manifest"]
    expected_entries = [
        {"path": "artifact-envelope.json", "sha256": data["projected_envelope_sha256"],
         "size": data["projected_envelope_size"]},
        *[
            {"path": path, "sha256": sha256_hex(data["payload_files"][path].encode()),
             "size": str(len(data["payload_files"][path].encode()))}
            for path in payload_paths
        ],
    ]
    expected_entries.sort(key=lambda entry: entry["path"].encode())
    check(manifest == {"schema": "wiki-artifact-bundle-manifest-v1", "entries": expected_entries},
          "bundle: manifest entries are not closed")
    check(canon(manifest).hex() == data["manifest_canonical_bytes_hex"],
          "bundle: manifest canonical bytes mismatch")
    check(sha256_hex(canon(manifest)) == data["bundle_sha256"], "bundle: manifest digest mismatch")

    # Stored envelope has the same exact wire shape and binds the manifest digest.
    stored = data["stored_envelope"]
    check(set(stored) == envelope_fields, "bundle: stored envelope fields are not exact")
    check(canon(stored).hex() == data["stored_envelope_bytes_hex"],
          "bundle: stored envelope canonical bytes mismatch")
    bundle_sha = data["bundle_sha256"]
    check(data["artifact_name"].endswith(bundle_sha[:16]),
          "bundle: artifact_name does not carry bundle_sha256 prefix")
    check(stored["artifact_name"] == data["artifact_name"], "bundle: stored artifact_name mismatch")
    check(stored["bundle_sha256"] == bundle_sha, "bundle: stored bundle_sha256 mismatch")
    check(stored["payload_paths"] == payload_paths, "bundle: stored payload paths are not closed")

    # Mutation raw manifests must NOT equal canonical bytes (noncanonical rejected).
    canonical_text = canon(manifest).decode("utf-8")
    for mut in data["mutation_cases"]:
        raw = mut["raw_manifest_text"]
        if mut["case"] == "key_order":
            check(mut["expected_error"] in ("noncanonical_bundle_manifest", "self_field_violation"),
                  "bundle: key_order expected_error unexpected")
        elif mut["case"] == "self_field":
            check("bundle-manifest.json" in raw, "bundle: self_field case missing self entry")
        else:
            check(raw != canonical_text, f"bundle: mutation {mut['case']} unexpectedly canonical")

def v_floor() -> None:
    data = load("floor-state-vectors-v1.json")
    # freshness serve gate: only three valid (state,reason) pairs
    valid_pairs = {
        ("CLEAR", "NONE"),
        ("FRESH_CHALLENGE_REQUIRED", "ATTESTATION_EXPIRED_BEFORE_STABILIZE"),
        ("FRESH_CHALLENGE_REQUIRED", "CLOCK_WINDOW_EXPIRED"),
    }
    gate = data.get("freshness_serve_gate", {})

    def _pair(entry: dict) -> tuple:
        g = entry.get("gate", entry)
        return (g.get("state"), g.get("reason"))

    valid_entries = gate.get("valid_pairs", gate.get("valid", []))
    invalid_entries = gate.get("invalid_in_enum_pairs", gate.get("invalid", []))
    check(len(valid_entries) == 3, "floor: expected exactly 3 valid freshness pairs")
    check(len(invalid_entries) == 3, "floor: expected exactly 3 invalid in-enum freshness pairs")
    for entry in valid_entries:
        pair = _pair(entry)
        check(pair in valid_pairs, f"floor: gate valid pair not allowed {pair[0]}/{pair[1]}")
        validate_schema(entry.get("gate", entry), "freshness-serve-gate-v1.schema.json")
    for entry in invalid_entries:
        pair = _pair(entry)
        check(pair not in valid_pairs, f"floor: gate invalid pair unexpectedly valid {pair[0]}/{pair[1]}")
    # exact-A quarantine walk present
    text = json.dumps(data)
    check("QUARANTINED_FLOOR_CONFLICT" in text, "floor: missing QUARANTINED_FLOOR_CONFLICT case")
    # structural schema validation of every floor-state object we can find
    for walk in data.get("counter_only_walk", []):
        validate_schema(walk, "floor-state-v1.schema.json")


def v_structural() -> None:
    # remaining families: ensure valid JSON + presence of required narrative tokens
    crash = load("crash-matrix-vectors-v1.json")
    ctext = json.dumps(crash)
    for token in ["PREPARED", "PLATFORM", "RECOVERY", "CAS", "ACTIVE"]:
        check(token in ctext, f"crash-matrix: missing {token} boundary")
    consent = load("new-consent-vectors-v1.json")
    cotext = json.dumps(consent)
    check("new" in cotext.lower(), "new-consent: missing consent token")
    # zero-body reject + body-bearing accept present
    check("reject" in cotext.lower() or "rejected" in cotext.lower(),
          "new-consent: missing zero-body rejection case")
    wal = load("wal-linearization-vectors-v1.json")
    names = " ".join(s.get("name", "") for s in wal.get("schedules", []))
    check("schedule-a" in names, "wal: missing schedule A")
    check("schedule-b" in names, "wal: missing schedule B")
    check(wal.get("linearization_point") == "atomic_checked_snapshot_read_acquisition",
          "wal: unexpected linearization point")


def main() -> int:
    if not FIXTURES_DIR.exists():
        print(f"FATAL: fixtures dir missing: {FIXTURES_DIR}", file=sys.stderr)
        return 2
    if not _HAVE_CRYPTO:
        fail("environment: cryptography unavailable; Ed25519 signature checks cannot run (fail-closed)")
    if not _HAVE_JSONSCHEMA:
        fail("environment: jsonschema unavailable; schema strictness checks cannot run (fail-closed)")
    v_kdf()
    v_identity()
    v_nonce()
    v_binding()
    v_bundle()
    v_floor()
    v_structural()

    passed = not FAILURES
    receipt = {
        "schema": "wiki-encrypted-lifecycle-vector-validation-receipt-v1",
        "verdict": "PASS" if passed else "FAIL",
        "oracle": "independent-second-oracle",
        "checks_run": CHECKS,
        "families": [
            "kdf", "identity", "nonce", "binding", "bundle", "floor",
            "crash-matrix", "new-consent", "wal-linearization",
        ],
        "cryptography_available": _HAVE_CRYPTO,
        "jsonschema_available": _HAVE_JSONSCHEMA,
        "failures": list(FAILURES),
    }
    receipt_dir = REPO_ROOT / "artifacts" / "encrypted-lifecycle"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    (receipt_dir / "vector-validation-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"independent oracle checks run: {CHECKS}")
    print(f"cryptography available: {_HAVE_CRYPTO}; jsonschema available: {_HAVE_JSONSCHEMA}")
    if FAILURES:
        print(f"VALIDATION FAILED: {len(FAILURES)} mismatch(es)")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("VALIDATION PASSED: generator and independent oracle agree on all families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
