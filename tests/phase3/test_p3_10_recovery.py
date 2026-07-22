from __future__ import annotations

from base64 import b64encode
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.recovery import (
    MINIMUM_RECOVERY_CATEGORIES,
    RECOVERY_SIGNING_DOMAIN,
    RECOVERY_SIGNING_PURPOSE,
    RecoveryCoordinator,
    RecoveryError,
    RecoveryItem,
    RecoveryItemCategory,
    RecoveryManifest,
    RecoveryQuerySpec,
    RecoverySignatureBinding,
    RecoveryTargetStatus,
    RecoveryTrustAnchor,
    SignedRecoveryManifest,
    recovery_state_root,
)
from wiki_spike.memory_core.registries import (
    HistoricalKeyRegistry,
    HistoricalPublicKey,
    signature_frame,
)

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = "ws-1"
SOURCE_GEN = "b" * 64
GENERATION = "a" * 64
RELEASE_OID = "c" * 40
SIGNED_AT = "2026-07-22T00:00:00Z"
COMPLETED_AT = "2026-07-22T00:05:00Z"


def raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def registry_snapshot(kind: str) -> bytes:
    if kind == "schema":
        body = {
            "registry_snapshot_version": "phase3-registry-snapshot-v1",
            "schemas": [],
            "write_versions": {},
            "migrations": [],
        }
    elif kind == "kind":
        body = {
            "registry_snapshot_version": "phase3-registry-snapshot-v1",
            "kinds": [],
        }
    else:
        raise AssertionError(kind)
    return canonical_bytes({**body, "snapshot_digest": sha256(canonical_bytes(body)).hexdigest()})


class Source:
    def __init__(self, signed, payloads):
        self.signed = signed
        self.payloads = dict(payloads)
        self.manifest_calls = 0
        self.read_calls = []
        self.replacement = None

    def signed_manifest(self, workspace_id):
        assert workspace_id == WORKSPACE
        self.manifest_calls += 1
        if self.replacement is not None and self.manifest_calls > 1:
            return self.replacement
        return self.signed

    def read_item(self, workspace_id, item_id):
        assert workspace_id == WORKSPACE
        self.read_calls.append(item_id)
        return self.payloads[item_id]


class Freeze:
    def __init__(self, allow=True, fail_release=False):
        self.allow = allow
        self.fail_release = fail_release
        self.acquired = []
        self.released = []

    def acquire(self, workspace_id, manifest_id):
        self.acquired.append((workspace_id, manifest_id))
        return "freeze-1" if self.allow else None

    def release(self, workspace_id, token):
        self.released.append((workspace_id, token))
        if self.fail_release:
            raise RuntimeError("release failed")


class Target:
    def __init__(self, bundle, *, fault=None):
        self.bundle = bundle
        self.fault = fault
        self.sessions = []
        self.staged = {}
        self.restored = []
        self.rebuilt = []
        self.committed = []
        self.aborted = []
        self.query_calls = []

    def begin_restore(self, manifest):
        if self.fault == "begin":
            raise RuntimeError("begin")
        session = f"session-{len(self.sessions) + 1}"
        self.sessions.append(session)
        self.staged[session] = {}
        return session

    def stage_item(self, session_id, item, payload):
        if self.fault == "stage" and not self.staged[session_id]:
            raise RuntimeError("stage")
        self.staged[session_id][item.item_id] = bytes(payload)

    def restore_authoritative(self, session_id, manifest):
        if self.fault == "restore":
            raise RuntimeError("restore")
        self.restored.append(session_id)
        return "0" * 64 if self.fault == "state_root" else manifest.state_root

    def rebuild_materializations(self, session_id, manifest):
        if self.fault == "rebuild":
            raise RuntimeError("rebuild")
        self.rebuilt.append(session_id)

    def status(self, session_id):
        manifest = self.bundle["manifest"]
        checkpoint = self.bundle["payloads"][manifest.control_plane_checkpoint_item_id]
        projections = [(name, manifest.publication_generation_id) for name in manifest.required_projection_names]
        state_root = manifest.state_root
        generation = manifest.publication_generation_id
        release = manifest.publication_release_commit_oid
        checkpoint_digest = sha256(checkpoint).hexdigest()
        if self.fault == "status_root":
            state_root = "0" * 64
        if self.fault == "publication":
            generation = "d" * 64
        if self.fault == "release_pointer":
            release = "e" * 40
        if self.fault == "checkpoint":
            checkpoint_digest = "0" * 64
        if self.fault == "projection":
            projections = [("identity", "d" * 64), ("chronology", generation)]
        return RecoveryTargetStatus(
            state_root,
            generation,
            release,
            checkpoint_digest,
            tuple(sorted(projections)),
        )

    def strict_query(self, session_id, query):
        self.query_calls.append(query.query_id)
        if self.fault == "query":
            return {"records": ["wrong"]}
        return self.bundle["query_result"]

    def commit_restore(self, session_id, manifest_id):
        if self.fault == "commit":
            raise RuntimeError("commit")
        self.committed.append((session_id, manifest_id))

    def abort_restore(self, session_id):
        self.aborted.append(session_id)


def build_bundle(*, include_artifact_key=True, bad_artifact_signature=False, include_sidecar=True):
    artifact_private = Ed25519PrivateKey.generate()
    recovery_private = Ed25519PrivateKey.generate()

    historical = HistoricalKeyRegistry()
    if include_artifact_key:
        record = HistoricalPublicKey.create(
            key_id="artifact-k1",
            public_key_bytes=raw_public(artifact_private),
            purposes=("generation", "release"),
            domains=("wiki.generation.v1", "wiki.release.v1"),
            valid_from="2026-07-01T00:00:00Z",
        )
        historical.register(record)
        historical.activate("artifact-k1", "generation", "wiki.generation.v1", at=SIGNED_AT)
        historical.activate("artifact-k1", "release", "wiki.release.v1", at=SIGNED_AT)
    key_snapshot = canonical_bytes(historical.snapshot())
    key_snapshot_digest = json.loads(key_snapshot)["snapshot_digest"]

    payloads_by_name = {
        "sidecar": b"encrypted-sidecar-v1",
        "cas": b"canonical-source-object-v1",
        "git_object": b"git-object-pack-v1",
        "git_ref": b"refs/wiki/generations/current\n",
        "generation": canonical_bytes({"generation_id": GENERATION, "state_root": "1" * 64}),
        "release": canonical_bytes({"generation_id": GENERATION, "release_oid": RELEASE_OID}),
        "keys": key_snapshot,
        "checkpoint": canonical_bytes(
            {
                "current_generation_id": GENERATION,
                "current_release_commit_oid": RELEASE_OID,
            }
        ),
        "schemas": registry_snapshot("schema"),
        "kinds": registry_snapshot("kind"),
    }

    items = {}
    if include_sidecar:
        items["sidecar"] = RecoveryItem.create(
            category=RecoveryItemCategory.SECRET_SIDECAR,
            logical_path="sidecars/secret-1.enc",
            payload=payloads_by_name["sidecar"],
            encrypted=True,
            encryption_key_id="enc-k1",
        )
    cas_dependencies = (items["sidecar"].item_id,) if include_sidecar else ()
    items.update(
        {
            "cas": RecoveryItem.create(
                category=RecoveryItemCategory.CAS_OBJECT,
                logical_path="cas/aa/object",
                payload=payloads_by_name["cas"],
                dependencies=cas_dependencies,
            ),
            "git_object": RecoveryItem.create(
                category=RecoveryItemCategory.GIT_OBJECT,
                logical_path="git/objects.pack",
                payload=payloads_by_name["git_object"],
            ),
            "git_ref": RecoveryItem.create(
                category=RecoveryItemCategory.GIT_REF,
                logical_path="git/refs.txt",
                payload=payloads_by_name["git_ref"],
            ),
            "generation": RecoveryItem.create(
                category=RecoveryItemCategory.GENERATION_MANIFEST,
                logical_path=f"manifests/generation/{GENERATION}.json",
                payload=payloads_by_name["generation"],
            ),
            "release": RecoveryItem.create(
                category=RecoveryItemCategory.RELEASE_MANIFEST,
                logical_path=f"manifests/release/{GENERATION}.json",
                payload=payloads_by_name["release"],
            ),
            "keys": RecoveryItem.create(
                category=RecoveryItemCategory.HISTORICAL_KEY_REGISTRY,
                logical_path="registries/historical-keys.json",
                payload=payloads_by_name["keys"],
            ),
            "checkpoint": RecoveryItem.create(
                category=RecoveryItemCategory.CONTROL_PLANE_CHECKPOINT,
                logical_path="control/checkpoint.json",
                payload=payloads_by_name["checkpoint"],
            ),
            "schemas": RecoveryItem.create(
                category=RecoveryItemCategory.SCHEMA_REGISTRY,
                logical_path="registries/schemas.json",
                payload=payloads_by_name["schemas"],
            ),
            "kinds": RecoveryItem.create(
                category=RecoveryItemCategory.KIND_REGISTRY,
                logical_path="registries/kinds.json",
                payload=payloads_by_name["kinds"],
            ),
        }
    )

    generation_signature = artifact_private.sign(
        signature_frame("generation", "wiki.generation.v1", payloads_by_name["generation"])
    )
    if bad_artifact_signature:
        generation_signature = b"x" * 64
    release_signature = artifact_private.sign(
        signature_frame("release", "wiki.release.v1", payloads_by_name["release"])
    )
    signatures = (
        RecoverySignatureBinding.create(
            payload_item_id=items["generation"].item_id,
            key_id="artifact-k1",
            purpose="generation",
            domain="wiki.generation.v1",
            signed_at=SIGNED_AT,
            signature=generation_signature,
        ),
        RecoverySignatureBinding.create(
            payload_item_id=items["release"].item_id,
            key_id="artifact-k1",
            purpose="release",
            domain="wiki.release.v1",
            signed_at=SIGNED_AT,
            signature=release_signature,
        ),
    )
    query_result = {"generation_id": GENERATION, "records": []}
    query = RecoveryQuerySpec.create(
        query_id="strict-current",
        query_type="memory.strict_get",
        as_of_generation_id=GENERATION,
        parameters={"object_id": "sample-1"},
        expected_result=query_result,
    )
    manifest = RecoveryManifest.create(
        workspace_id=WORKSPACE,
        source_generation_id=SOURCE_GEN,
        publication_generation_id=GENERATION,
        publication_release_commit_oid=RELEASE_OID,
        key_registry_item_id=items["keys"].item_id,
        schema_registry_item_id=items["schemas"].item_id,
        kind_registry_item_id=items["kinds"].item_id,
        control_plane_checkpoint_item_id=items["checkpoint"].item_id,
        required_projection_names=("identity", "chronology"),
        items=tuple(items.values()),
        signatures=signatures,
        sample_queries=(query,),
    )
    signed = SignedRecoveryManifest.sign(
        manifest,
        signer_key_id="recovery-k1",
        private_key=recovery_private,
        signed_at=SIGNED_AT,
    )
    trust = RecoveryTrustAnchor.create(
        workspace_id=WORKSPACE,
        recovery_signer_key_id="recovery-k1",
        recovery_signer_public_key=raw_public(recovery_private),
        key_registry_snapshot_digest=key_snapshot_digest,
        expected_manifest_id=manifest.manifest_id,
    )
    payloads = {item.item_id: payloads_by_name[name] for name, item in items.items()}
    return {
        "artifact_private": artifact_private,
        "recovery_private": recovery_private,
        "items": items,
        "payloads": payloads,
        "manifest": manifest,
        "signed": signed,
        "trust": trust,
        "query_result": query_result,
    }


def coordinator(bundle, *, source=None, target=None, freeze=None):
    return RecoveryCoordinator(
        source or Source(bundle["signed"], bundle["payloads"]),
        bundle["trust"],
        target=target,
        freeze=freeze,
        completed_at=COMPLETED_AT,
    )


def test_valid_dry_run_verifies_all_items_signatures_and_queries():
    bundle = build_bundle()
    source = Source(bundle["signed"], bundle["payloads"])
    evidence = coordinator(bundle, source=source).dry_run(WORKSPACE)
    assert evidence.status == "verified"
    assert evidence.manifest_id == bundle["manifest"].manifest_id
    assert evidence.verified_item_count == str(len(bundle["manifest"].items))
    assert evidence.verified_signature_count == "2"
    assert set(source.read_calls) == set(bundle["payloads"])
    assert b"canonical-source-object" not in evidence.canonical_bytes()


def test_manifest_creation_is_order_independent_and_content_bound():
    bundle = build_bundle()
    manifest = bundle["manifest"]
    rebuilt = RecoveryManifest.create(
        workspace_id=manifest.workspace_id,
        source_generation_id=manifest.source_generation_id,
        publication_generation_id=manifest.publication_generation_id,
        publication_release_commit_oid=manifest.publication_release_commit_oid,
        key_registry_item_id=manifest.key_registry_item_id,
        schema_registry_item_id=manifest.schema_registry_item_id,
        kind_registry_item_id=manifest.kind_registry_item_id,
        control_plane_checkpoint_item_id=manifest.control_plane_checkpoint_item_id,
        required_projection_names=tuple(reversed(manifest.required_projection_names)),
        items=tuple(reversed(manifest.items)),
        signatures=tuple(reversed(manifest.signatures)),
        sample_queries=tuple(reversed(manifest.sample_queries)),
    )
    assert rebuilt.manifest_id == manifest.manifest_id
    assert rebuilt.canonical_bytes() == manifest.canonical_bytes()


def test_unknown_manifest_field_fails_closed():
    bundle = build_bundle()
    data = bundle["manifest"].to_mapping()
    data["unexpected"] = "x"
    with pytest.raises(UnknownContractField):
        RecoveryManifest.from_mapping(data)


def test_manifest_signature_tamper_is_rejected():
    bundle = build_bundle()
    tampered = replace(bundle["signed"], signature_b64=b64encode(b"x" * 64).decode("ascii"))
    with pytest.raises(RecoveryError, match="signature") as exc:
        coordinator(bundle, source=Source(tampered, bundle["payloads"])).dry_run(WORKSPACE)
    assert exc.value.error_code == "manifest_signature_invalid"


def test_trust_anchor_manifest_pin_prevents_rollback_or_substitution():
    bundle = build_bundle()
    bad_trust = RecoveryTrustAnchor.create(
        workspace_id=WORKSPACE,
        recovery_signer_key_id=bundle["trust"].recovery_signer_key_id,
        recovery_signer_public_key=__import__("base64").b64decode(
            bundle["trust"].recovery_signer_public_key_b64
        ),
        key_registry_snapshot_digest=bundle["trust"].key_registry_snapshot_digest,
        expected_manifest_id="0" * 64,
    )
    with pytest.raises(RecoveryError) as exc:
        RecoveryCoordinator(
            Source(bundle["signed"], bundle["payloads"]),
            bad_trust,
            completed_at=COMPLETED_AT,
        ).dry_run(WORKSPACE)
    assert exc.value.error_code == "trust_anchor_mismatch"


def test_missing_required_item_fails_before_target_mutation():
    bundle = build_bundle()
    source = Source(bundle["signed"], bundle["payloads"])
    source.payloads.pop(bundle["items"]["cas"].item_id)
    target = Target(bundle)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, source=source, target=target, freeze=Freeze()).restore(WORKSPACE)
    assert exc.value.error_code == "missing_item"
    assert target.sessions == []


@pytest.mark.parametrize("mode", ["digest", "length"])
def test_corrupt_item_digest_or_length_is_rejected(mode):
    bundle = build_bundle()
    source = Source(bundle["signed"], bundle["payloads"])
    item_id = bundle["items"]["cas"].item_id
    original = source.payloads[item_id]
    source.payloads[item_id] = (b"X" * len(original)) if mode == "digest" else original[:-1]
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, source=source).dry_run(WORKSPACE)
    assert exc.value.error_code == ("item_digest_mismatch" if mode == "digest" else "item_length_mismatch")


def test_historical_key_registry_digest_is_pinned_out_of_band():
    bundle = build_bundle()
    bad_trust = RecoveryTrustAnchor.create(
        workspace_id=WORKSPACE,
        recovery_signer_key_id=bundle["trust"].recovery_signer_key_id,
        recovery_signer_public_key=__import__("base64").b64decode(
            bundle["trust"].recovery_signer_public_key_b64
        ),
        key_registry_snapshot_digest="0" * 64,
        expected_manifest_id=bundle["trust"].expected_manifest_id,
    )
    with pytest.raises(RecoveryError) as exc:
        RecoveryCoordinator(
            Source(bundle["signed"], bundle["payloads"]),
            bad_trust,
            completed_at=COMPLETED_AT,
        ).dry_run(WORKSPACE)
    assert exc.value.error_code == "trust_anchor_mismatch"


def test_missing_historical_verification_key_rejects_signed_artifact():
    bundle = build_bundle(include_artifact_key=False)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle).dry_run(WORKSPACE)
    assert exc.value.error_code == "artifact_signature_invalid"


def test_bad_artifact_signature_is_rejected():
    bundle = build_bundle(bad_artifact_signature=True)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle).dry_run(WORKSPACE)
    assert exc.value.error_code == "artifact_signature_invalid"


def test_missing_secret_sidecar_is_rejected():
    bundle = build_bundle()
    source = Source(bundle["signed"], bundle["payloads"])
    source.payloads.pop(bundle["items"]["sidecar"].item_id)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, source=source).dry_run(WORKSPACE)
    assert exc.value.error_code == "missing_item"


def test_secret_sidecar_must_be_encrypted():
    with pytest.raises(InvalidContractValue, match="must be encrypted"):
        RecoveryItem.create(
            category=RecoveryItemCategory.SECRET_SIDECAR,
            logical_path="sidecars/plain.txt",
            payload=b"plain",
        )


def test_manifest_requires_complete_minimum_recovery_set():
    bundle = build_bundle()
    items = tuple(item for item in bundle["manifest"].items if item.category != RecoveryItemCategory.GIT_OBJECT.value)
    assert RecoveryItemCategory.GIT_OBJECT in MINIMUM_RECOVERY_CATEGORIES
    with pytest.raises(InvalidContractValue, match="categories missing"):
        RecoveryManifest.create(
            workspace_id=WORKSPACE,
            source_generation_id=SOURCE_GEN,
            publication_generation_id=GENERATION,
            publication_release_commit_oid=RELEASE_OID,
            key_registry_item_id=bundle["manifest"].key_registry_item_id,
            schema_registry_item_id=bundle["manifest"].schema_registry_item_id,
            kind_registry_item_id=bundle["manifest"].kind_registry_item_id,
            control_plane_checkpoint_item_id=bundle["manifest"].control_plane_checkpoint_item_id,
            required_projection_names=("chronology", "identity"),
            items=items,
            signatures=bundle["manifest"].signatures,
            sample_queries=bundle["manifest"].sample_queries,
        )


def test_missing_dependency_is_rejected_by_manifest():
    bundle = build_bundle(include_sidecar=False)
    cas = bundle["items"]["cas"]
    forged = RecoveryItem.create(
        category=RecoveryItemCategory.CAS_OBJECT,
        logical_path=cas.logical_path,
        payload=bundle["payloads"][cas.item_id],
        dependencies=("0" * 64,),
    )
    items = tuple(forged if item.item_id == cas.item_id else item for item in bundle["manifest"].items)
    with pytest.raises(InvalidContractValue, match="missing dependency"):
        RecoveryManifest.create(
            workspace_id=WORKSPACE,
            source_generation_id=SOURCE_GEN,
            publication_generation_id=GENERATION,
            publication_release_commit_oid=RELEASE_OID,
            key_registry_item_id=bundle["manifest"].key_registry_item_id,
            schema_registry_item_id=bundle["manifest"].schema_registry_item_id,
            kind_registry_item_id=bundle["manifest"].kind_registry_item_id,
            control_plane_checkpoint_item_id=bundle["manifest"].control_plane_checkpoint_item_id,
            required_projection_names=("chronology", "identity"),
            items=items,
            signatures=bundle["manifest"].signatures,
            sample_queries=bundle["manifest"].sample_queries,
        )


def test_dry_run_is_read_only_and_does_not_acquire_freeze_or_target():
    bundle = build_bundle()
    freeze = Freeze()
    target = Target(bundle)
    evidence = coordinator(bundle, target=target, freeze=freeze).dry_run(WORKSPACE)
    assert evidence.status == "verified"
    assert freeze.acquired == []
    assert target.sessions == []


def test_clean_room_restore_rebuilds_and_verifies_before_commit():
    bundle = build_bundle()
    freeze = Freeze()
    target = Target(bundle)
    evidence = coordinator(bundle, target=target, freeze=freeze).restore(WORKSPACE)
    assert evidence.status == "restored"
    assert len(target.staged[target.sessions[0]]) == len(bundle["manifest"].items)
    assert target.restored == target.sessions
    assert target.rebuilt == target.sessions
    assert target.query_calls == ["strict-current"]
    assert target.committed == [(target.sessions[0], bundle["manifest"].manifest_id)]
    assert target.aborted == []
    assert freeze.released == [(WORKSPACE, "freeze-1")]


def test_write_freeze_failure_prevents_restore_session():
    bundle = build_bundle()
    target = Target(bundle)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, target=target, freeze=Freeze(allow=False)).restore(WORKSPACE)
    assert exc.value.error_code == "write_freeze_unavailable"
    assert target.sessions == []


def test_manifest_change_after_freeze_is_rejected():
    bundle = build_bundle()
    source = Source(bundle["signed"], bundle["payloads"])
    other = build_bundle()
    source.replacement = other["signed"]
    target = Target(bundle)
    freeze = Freeze()
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, source=source, target=target, freeze=freeze).restore(WORKSPACE)
    assert exc.value.error_code == "manifest_changed"
    assert target.sessions == []
    assert freeze.released


@pytest.mark.parametrize(
    ("fault", "error_code"),
    [
        ("state_root", "state_root_mismatch"),
        ("status_root", "state_root_mismatch"),
        ("publication", "publication_pointer_mismatch"),
        ("release_pointer", "publication_pointer_mismatch"),
        ("checkpoint", "checkpoint_mismatch"),
        ("projection", "projection_pointer_mismatch"),
        ("query", "query_verification_failed"),
    ],
)
def test_post_restore_verification_failures_abort_and_release(fault, error_code):
    bundle = build_bundle()
    target = Target(bundle, fault=fault)
    freeze = Freeze()
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, target=target, freeze=freeze).restore(WORKSPACE)
    assert exc.value.error_code == error_code
    assert target.aborted == target.sessions
    assert target.committed == []
    assert freeze.released == [(WORKSPACE, "freeze-1")]


@pytest.mark.parametrize("fault", ["begin", "stage", "restore", "rebuild", "commit"])
def test_adapter_failures_never_leave_freeze_held(fault):
    bundle = build_bundle()
    target = Target(bundle, fault=fault)
    freeze = Freeze()
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, target=target, freeze=freeze).restore(WORKSPACE)
    assert exc.value.error_code == "restore_failed"
    if target.sessions:
        assert target.aborted == target.sessions
    assert freeze.released == [(WORKSPACE, "freeze-1")]


def test_freeze_release_failure_is_reported_even_after_successful_restore():
    bundle = build_bundle()
    target = Target(bundle)
    freeze = Freeze(fail_release=True)
    with pytest.raises(RecoveryError) as exc:
        coordinator(bundle, target=target, freeze=freeze).restore(WORKSPACE)
    assert exc.value.error_code == "write_freeze_release_failed"
    assert target.committed


def test_public_core_import_stays_storage_independent():
    code = """
import sys
import wiki_spike.memory_core
forbidden = {'wiki_spike.cas','wiki_spike.controlplane','wiki_spike.generation','wiki_spike.publish','wiki_spike.workspace','wiki_spike.signing'}
assert not forbidden.intersection(sys.modules), forbidden.intersection(sys.modules)
"""
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    subprocess.run([sys.executable, "-c", code], check=True, env=env)


def test_recovery_contract_schema_is_strict():
    schema = json.loads((ROOT / "schemas/phase3/recovery-contracts.schema.json").read_text("utf-8"))
    for name in (
        "recoveryItem",
        "signatureBinding",
        "recoveryQuery",
        "recoveryManifest",
        "signedRecoveryManifest",
        "recoveryTrustAnchor",
        "recoveryEvidence",
    ):
        assert schema["$defs"][name]["additionalProperties"] is False


def test_adversarial_report_contains_exactly_20_rounds():
    import re

    text = (ROOT / "docs/adversarial/P3-10_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))


def write_filesystem_bundle(tmp_path, bundle):
    bundle_dir = tmp_path / "bundle"
    items_dir = bundle_dir / "items"
    items_dir.mkdir(parents=True)
    (bundle_dir / "recovery-manifest.json").write_bytes(bundle["signed"].canonical_bytes())
    for item_id, payload in bundle["payloads"].items():
        (items_dir / item_id).write_bytes(payload)
    trust_path = tmp_path / "recovery-trust.json"
    trust_path.write_bytes(canonical_bytes(bundle["trust"].to_mapping()))
    return bundle_dir, trust_path


def test_filesystem_dry_run_cli_contract_writes_minimized_evidence(tmp_path):
    from scripts.p3_10_recovery_dry_run import run_dry_run

    bundle = build_bundle()
    bundle_dir, trust_path = write_filesystem_bundle(tmp_path, bundle)
    evidence = run_dry_run(
        bundle_dir=bundle_dir,
        trust_anchor_path=trust_path,
        workspace_id=WORKSPACE,
        completed_at=COMPLETED_AT,
    )
    assert evidence.status == "verified"
    raw = evidence.canonical_bytes()
    assert b"encrypted-sidecar" not in raw
    assert b"canonical-source-object" not in raw


def test_filesystem_dry_run_rejects_noncanonical_manifest(tmp_path):
    from scripts.p3_10_recovery_dry_run import DryRunInputError, FilesystemRecoverySource

    bundle = build_bundle()
    bundle_dir, _ = write_filesystem_bundle(tmp_path, bundle)
    value = json.loads((bundle_dir / "recovery-manifest.json").read_text("utf-8"))
    (bundle_dir / "recovery-manifest.json").write_text(json.dumps(value, indent=2), "utf-8")
    with pytest.raises(DryRunInputError, match="not canonical"):
        FilesystemRecoverySource(bundle_dir)


def test_signed_generation_and_release_items_require_signature_bindings():
    bundle = build_bundle()
    manifest = bundle["manifest"]
    with pytest.raises(InvalidContractValue, match="required purpose/domain"):
        RecoveryManifest.create(
            workspace_id=manifest.workspace_id,
            source_generation_id=manifest.source_generation_id,
            publication_generation_id=manifest.publication_generation_id,
            publication_release_commit_oid=manifest.publication_release_commit_oid,
            key_registry_item_id=manifest.key_registry_item_id,
            schema_registry_item_id=manifest.schema_registry_item_id,
            kind_registry_item_id=manifest.kind_registry_item_id,
            control_plane_checkpoint_item_id=manifest.control_plane_checkpoint_item_id,
            required_projection_names=manifest.required_projection_names,
            items=manifest.items,
            signatures=(),
            sample_queries=manifest.sample_queries,
        )


def test_unsupported_registry_snapshot_version_is_rejected():
    value = json.loads(registry_snapshot("schema"))
    body = {k: v for k, v in value.items() if k != "snapshot_digest"}
    body["registry_snapshot_version"] = "phase3-registry-snapshot-v999"
    forged_payload = canonical_bytes(
        {**body, "snapshot_digest": sha256(canonical_bytes(body)).hexdigest()}
    )
    with pytest.raises(RecoveryError) as exc:
        RecoveryCoordinator._verify_registry_snapshot(
            forged_payload,
            label="schema registry",
            required_keys={
                "registry_snapshot_version", "schemas", "write_versions",
                "migrations", "snapshot_digest",
            },
        )
    assert exc.value.error_code == "registry_invalid"


def test_signed_artifact_purpose_and_domain_are_category_bound():
    bundle = build_bundle()
    manifest = bundle["manifest"]
    generation_binding = next(
        binding for binding in manifest.signatures
        if binding.payload_item_id == bundle["items"]["generation"].item_id
    )
    wrong = RecoverySignatureBinding.create(
        payload_item_id=generation_binding.payload_item_id,
        key_id=generation_binding.key_id,
        purpose="release",
        domain="wiki.release.v1",
        signed_at=SIGNED_AT,
        signature=b"x" * 64,
    )
    signatures = tuple(
        wrong if binding.binding_id == generation_binding.binding_id else binding
        for binding in manifest.signatures
    )
    with pytest.raises(InvalidContractValue, match="required purpose/domain"):
        RecoveryManifest.create(
            workspace_id=manifest.workspace_id,
            source_generation_id=manifest.source_generation_id,
            publication_generation_id=manifest.publication_generation_id,
            publication_release_commit_oid=manifest.publication_release_commit_oid,
            key_registry_item_id=manifest.key_registry_item_id,
            schema_registry_item_id=manifest.schema_registry_item_id,
            kind_registry_item_id=manifest.kind_registry_item_id,
            control_plane_checkpoint_item_id=manifest.control_plane_checkpoint_item_id,
            required_projection_names=manifest.required_projection_names,
            items=manifest.items,
            signatures=signatures,
            sample_queries=manifest.sample_queries,
        )
