from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import runpy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_stage3_ledger_persistence import digest
from test_stage6_cutover import _cohort, _decision, _scope
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    ACTIVATION_RECEIPT_V1,
    CONSENT_TRANSFER_RECEIPT_V1,
    DECOMMISSION_CERTIFICATE_V1,
    ActivationReceiptV1,
    ConsentTransferReceiptV1,
    DecommissionCertificateV1,
)


CLI = Path(__file__).parents[2] / "scripts" / "second_brain_decommission_certificate.py"


def _write(path: Path, value: dict[str, object]) -> Path:
    # CutoverDecisionV1 intentionally has integer metric fields; its canonical
    # wire is compact sorted JSON, whereas Core's hash-only serializer rejects
    # raw numbers by design.
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode())
    return path


def _signed(key: Ed25519PrivateKey, domain: str, body: dict[str, object]) -> str:
    return b64encode(key.sign(canonical_bytes({"domain": domain, "body": body}))).decode("ascii")


_ACTIVATION_DOMAIN = "wiki-spike.second-brain.activation.v1"
_CONSENT_DOMAIN = "wiki-spike.second-brain.consent-transfer.v1"
_APPROVAL_DOMAIN = "wiki-spike.second-brain.decommission-approval.v1"
_CERTIFICATE_DOMAIN = "wiki-spike.second-brain.decommission-certificate.v1"


class _Authority:
    """Deployment fake with out-of-band signer and approval registries."""

    def __init__(self, keys: dict[tuple[str, str], Ed25519PrivateKey], approvals: dict[str, dict[str, object]], now: str) -> None:
        self._keys = keys
        self._trusted = {identity: key.public_key() for identity, key in keys.items()}
        self._approvals, self._now = approvals, now
        self.signature_verification_domains: list[str] = []

    def _verify(self, *, signer_ref: str, key_id: str, signature: str, domain: str, body: dict[str, object]) -> None:
        self.signature_verification_domains.append(domain)
        key = self._trusted.get((signer_ref, key_id))
        if key is None or body.get("signer_algorithm") != "Ed25519":
            raise ValueError("untrusted signer")
        key.verify(b64decode(signature, validate=True), canonical_bytes({"domain": domain, "body": body}))

    def _verify_approvals(self, activation, request) -> None:
        records = []
        for expected, reference in zip(("migration", "product", "quality", "security"), activation.approval_digests, strict=True):
            if reference.role != expected:
                raise ValueError("approval order")
            record = self._approvals.get(reference.approval_digest)
            if record is None:
                raise ValueError("unknown approval")
            body = record["body"]
            if not isinstance(body, dict) or sha256(canonical_bytes(record)).hexdigest() != reference.approval_digest:
                raise ValueError("approval digest")
            if (body.get("role"), body.get("workspace_ref"), body.get("source_ref"), body.get("decision_digest")) != (expected, request.workspace_ref, request.source_ref, request.cutover_decision_digest):
                raise ValueError("approval scope")
            if not (body.get("issued_at") <= self._now < body.get("expires_at")):
                raise ValueError("approval freshness")
            self._verify(signer_ref=body["signer_ref"], key_id=body["key_id"], signature=record["signature"], domain=_APPROVAL_DOMAIN, body=body)
            records.append(reference.approval_digest)
        if len(set(records)) != 4:
            raise ValueError("duplicate approval")

    def issue_decommission_certificate(self, request, *, activation, consent_transfer):
        self._verify(signer_ref=activation.signer_ref, key_id=activation.key_id, signature=activation.signature, domain=_ACTIVATION_DOMAIN, body=activation.body())
        self._verify(signer_ref=consent_transfer.signer_ref, key_id=consent_transfer.key_id, signature=consent_transfer.signature, domain=_CONSENT_DOMAIN, body=consent_transfer.body())
        if self._now < request.retention_end or not (consent_transfer.issued_at <= self._now < consent_transfer.expires_at):
            raise ValueError("authority-refusal")
        if (activation.route_authority, activation.route_state_digest, activation.route_receipt_digest, activation.state) != ("route-authority:deployment", digest("route-state"), digest("route-receipt"), "CANONICAL_MUTATED"):
            raise ValueError("route activation")
        if (activation.workspace_ref, activation.source_ref, activation.activation_digest, activation.cutover_decision_digest) != (request.workspace_ref, request.source_ref, request.activation_digest, request.cutover_decision_digest):
            raise ValueError("activation binding")
        if (consent_transfer.workspace_ref, consent_transfer.source_ref, consent_transfer.activation_digest, consent_transfer.cutover_decision_digest, consent_transfer.conservation_receipt_sha256, consent_transfer.allowlist_digest) != (request.workspace_ref, request.source_ref, request.activation_digest, request.cutover_decision_digest, request.conservation_receipt_sha256, request.allowlist_digest):
            raise ValueError("consent binding")
        self._verify_approvals(activation, request)
        body = {
            "decommission_certificate_version": DECOMMISSION_CERTIFICATE_V1,
            "request": request.to_mapping(), "request_digest": request.request_digest,
            "verified_at": self._now, "retention_seconds": "7776000", "state": "ROLLBACK_CLOSED",
            "destructive_action_authorized": False, "signer_ref": "signer:certificate",
            "signer_algorithm": "Ed25519", "key_id": "key:certificate",
        }
        certificate_key = self._keys[("signer:certificate", "key:certificate")]
        return DecommissionCertificateV1.from_mapping(body | {
            "certificate_digest": sha256(canonical_bytes(body)).hexdigest(), "signature": _signed(certificate_key, _CERTIFICATE_DOMAIN, body),
        })

    def verify_issued_decommission_certificate(self, certificate) -> bool:
        try:
            self._verify(signer_ref=certificate.signer_ref, key_id=certificate.key_id, signature=certificate.signature, domain=_CERTIFICATE_DOMAIN, body=certificate.body())
        except Exception:
            return False
        return certificate.signer_ref == "signer:certificate" and certificate.key_id == "key:certificate"


def _conservation() -> dict[str, object]:
    reconcile = runpy.run_path(str(Path(__file__).parents[2] / "scripts" / "second_brain_reconcile.py"))
    request = reconcile["ReconciliationRequestV1"]("second-brain-reconcile-v1", *(digest(f"reconcile-{n}") for n in range(4)))
    result = reconcile["ReconciliationResultV1"](
        "PASS", False, False, reconcile["ReconciliationCoverageV1"]("0", "0", "0", "0"), ()
    )
    aggregate = reconcile["ReconciliationAggregateDigestsV1"](*(digest(f"aggregate-{n}") for n in range(7)))
    return reconcile["reconciliation_receipt_mapping"](
        request, result, aggregate, verification_mode="RESTORE_RECALL_VERIFIED",
        recall_sample_digest=digest("sample"), isolated_restore_target_digest=digest("restore"),
        deterministic_recall_digest=digest("recall"),
    )


def _files(tmp_path: Path):
    keys = {
        ("signer:activation", "key:activation"): Ed25519PrivateKey.generate(),
        ("signer:consent", "key:consent"): Ed25519PrivateKey.generate(),
        ("signer:approval", "key:approval"): Ed25519PrivateKey.generate(),
        ("signer:certificate", "key:certificate"): Ed25519PrivateKey.generate(),
    }
    scope, cohort = _scope(), _cohort(_scope())
    decision = _decision(scope, cohort)
    activated = "2026-01-01T00:00:00Z"
    approvals_registry: dict[str, dict[str, object]] = {}
    approvals = []
    for role in ("migration", "product", "quality", "security"):
        approval_body: dict[str, object] = {"approval_version": "test-approval-v1", "role": role, "workspace_ref": decision.workspace_ref, "source_ref": "unified-db", "decision_digest": decision.decision_digest, "issued_at": "2026-03-01T00:00:00Z", "expires_at": "2026-04-15T00:00:00Z", "signer_ref": "signer:approval", "signer_algorithm": "Ed25519", "key_id": "key:approval"}
        sealed: dict[str, object] = {"body": approval_body, "signature": _signed(keys[("signer:approval", "key:approval")], _APPROVAL_DOMAIN, approval_body)}
        approval_digest = sha256(canonical_bytes(sealed)).hexdigest()
        approvals_registry[approval_digest] = sealed
        approvals.append({"role": role, "approval_digest": approval_digest})
    activation_body: dict[str, object] = {
        "activation_receipt_version": ACTIVATION_RECEIPT_V1, "workspace_ref": decision.workspace_ref,
        "source_ref": "unified-db", "route_authority": "route-authority:deployment",
        "route_state_digest": digest("route-state"), "route_receipt_digest": digest("route-receipt"),
        "cutover_decision_digest": decision.decision_digest, "cohort_manifest_digest": cohort.manifest_digest,
        "activated_at": activated, "approval_digests": approvals, "state": "CANONICAL_MUTATED",
        "live_operation_authorized": False, "signer_ref": "signer:activation", "signer_algorithm": "Ed25519", "key_id": "key:activation",
    }
    activation = activation_body | {"activation_digest": sha256(canonical_bytes(activation_body)).hexdigest()}
    activation["signature"] = _signed(keys[("signer:activation", "key:activation")], _ACTIVATION_DOMAIN, activation_body)
    conservation = _conservation()
    conservation_sha = sha256(canonical_bytes(conservation)).hexdigest()
    consent_body: dict[str, object] = {
        "consent_transfer_receipt_version": CONSENT_TRANSFER_RECEIPT_V1, "workspace_ref": decision.workspace_ref,
        "source_ref": "unified-db", "activation_digest": activation["activation_digest"],
        "cutover_decision_digest": decision.decision_digest, "conservation_receipt_sha256": conservation_sha,
        "allowlist_digest": digest("allowlist"), "consent_ref": "consent:transfer", "retention_revision": "1",
        "transfer_state": "TRANSFERRED", "issued_at": activated, "expires_at": "2026-05-01T00:00:00Z",
        "live_operation_authorized": False, "signer_ref": "signer:consent", "signer_algorithm": "Ed25519", "key_id": "key:consent",
    }
    consent = consent_body | {"receipt_digest": sha256(canonical_bytes(consent_body)).hexdigest()}
    consent["signature"] = _signed(keys[("signer:consent", "key:consent")], _CONSENT_DOMAIN, consent_body)
    return keys, approvals_registry, decision, {
        "activation": _write(tmp_path / "activation.json", activation), "decision": _write(tmp_path / "decision.json", decision.to_mapping()),
        "conservation": _write(tmp_path / "conservation.json", conservation), "consent": _write(tmp_path / "consent.json", consent),
        "allowlist": digest("allowlist"), "retention_end": "2026-04-01T00:00:00Z",
    }


def _argv(paths, out: Path) -> list[str]:
    return ["verify", "--activation", str(paths["activation"]), "--retention-end", paths["retention_end"], "--decision", str(paths["decision"]), "--conservation", str(paths["conservation"]), "--allowlist-digest", paths["allowlist"], "--consent-transfer", str(paths["consent"]), "--out", str(out)]


def _reseal(document: dict[str, object], *, digest_field: str, key: Ed25519PrivateKey, domain: str) -> None:
    body = {field: value for field, value in document.items() if field not in {digest_field, "signature"}}
    document[digest_field] = sha256(canonical_bytes(body)).hexdigest()
    document["signature"] = _signed(key, domain, body)


def _replace_approval(approvals, activation: dict[str, object], keys, index: int, **changes: object) -> None:
    reference = activation["approval_digests"][index]
    old_digest = reference["approval_digest"]
    sealed = approvals.pop(old_digest)
    body = dict(sealed["body"])
    body.update(changes)
    sealed = {"body": body, "signature": _signed(keys[("signer:approval", "key:approval")], _APPROVAL_DOMAIN, body)}
    new_digest = sha256(canonical_bytes(sealed)).hexdigest()
    approvals[new_digest] = sealed
    reference["approval_digest"] = new_digest
    _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)


def test_exact_90_day_injected_certificate_is_canonical_and_non_destructive(tmp_path: Path) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    out = tmp_path / "certificate.json"
    assert script["run_with_authority"](_argv(paths, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 0
    raw = out.read_bytes()
    certificate = DecommissionCertificateV1.from_mapping(json.loads(raw))
    assert raw == canonical_bytes(certificate.to_mapping())
    assert certificate.verified_at == paths["retention_end"]
    assert certificate.destructive_action_authorized is False
    assert certificate.request.retention_end == paths["retention_end"]


def test_retention_must_be_exact_and_authority_clock_must_have_elapsed(tmp_path: Path) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    for retention_end in ("2026-03-31T00:00:00Z", "2026-03-31T23:59:59Z", "2026-04-01T00:00:01Z"):
        altered = dict(paths, retention_end=retention_end)
        assert script["run_with_authority"](_argv(altered, tmp_path / f"{retention_end[-3:]}.json"), authority=_Authority(keys, approvals, "2026-04-01T00:00:00Z")) == 2
    assert script["run_with_authority"](_argv(paths, tmp_path / "early.json"), authority=_Authority(keys, approvals, "2026-03-31T23:59:59Z")) == 2


def test_dtos_close_self_digests_and_signatures_structurally(tmp_path: Path) -> None:
    _, _, _, paths = _files(tmp_path)
    activation = ActivationReceiptV1.from_mapping(json.loads(paths["activation"].read_text()))
    consent = ConsentTransferReceiptV1.from_mapping(json.loads(paths["consent"].read_text()))
    assert activation.state == "CANONICAL_MUTATED" and consent.transfer_state == "TRANSFERRED"


@pytest.mark.parametrize("case", ("activation-signature", "activation-self-digest", "activation-untrusted", "activation-state", "activation-route", "activation-source", "activation-workspace", "activation-decision", "activation-cohort", "consent-signature", "consent-self-digest", "consent-untrusted", "consent-expired", "consent-not-yet-valid", "consent-source", "consent-activation", "consent-decision", "consent-conservation", "consent-allowlist"))
def test_deployment_registry_refuses_bad_activation_and_consent_evidence(tmp_path: Path, case: str) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    activation = json.loads(paths["activation"].read_text())
    consent = json.loads(paths["consent"].read_text())
    if case == "activation-signature":
        activation["signature"] = b64encode(b"x" * 64).decode("ascii")
    elif case == "activation-self-digest":
        activation["activation_digest"] = "0" * 64
    elif case == "activation-untrusted":
        activation["signer_ref"] = "signer:untrusted"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-state":
        activation["state"] = "ROUTE_SWITCHED_NO_MUTATION"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-route":
        activation["route_authority"] = "route-authority:wrong"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-source":
        activation["source_ref"] = "wrong-source"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-workspace":
        activation["workspace_ref"] = "workspace:wrong"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-decision":
        activation["cutover_decision_digest"] = digest("wrong-decision")
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "activation-cohort":
        activation["cohort_manifest_digest"] = digest("wrong-cohort")
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "consent-signature":
        consent["signature"] = b64encode(b"x" * 64).decode("ascii")
    elif case == "consent-self-digest":
        consent["receipt_digest"] = "0" * 64
    elif case == "consent-untrusted":
        consent["key_id"] = "key:untrusted"
        _reseal(consent, digest_field="receipt_digest", key=keys[("signer:consent", "key:consent")], domain=_CONSENT_DOMAIN)
    elif case == "consent-expired":
        consent["expires_at"] = "2026-03-31T23:59:59Z"
        _reseal(consent, digest_field="receipt_digest", key=keys[("signer:consent", "key:consent")], domain=_CONSENT_DOMAIN)
    elif case == "consent-not-yet-valid":
        consent["issued_at"] = "2026-04-01T00:00:01Z"; consent["expires_at"] = "2026-05-01T00:00:00Z"
        _reseal(consent, digest_field="receipt_digest", key=keys[("signer:consent", "key:consent")], domain=_CONSENT_DOMAIN)
    else:
        if case == "consent-source": consent["source_ref"] = "wrong-source"
        elif case == "consent-activation": consent["activation_digest"] = digest("wrong-activation")
        elif case == "consent-decision": consent["cutover_decision_digest"] = digest("wrong-decision")
        elif case == "consent-conservation": consent["conservation_receipt_sha256"] = digest("wrong-conservation")
        else: consent["allowlist_digest"] = digest("wrong-allowlist")
        _reseal(consent, digest_field="receipt_digest", key=keys[("signer:consent", "key:consent")], domain=_CONSENT_DOMAIN)
    _write(paths["activation"], activation); _write(paths["consent"], consent)
    out = tmp_path / f"{case}.json"
    assert script["run_with_authority"](_argv(paths, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 2
    assert not out.exists()


@pytest.mark.parametrize("case", ("unknown", "duplicate", "wrong-role", "wrong-order", "wrong-workspace", "wrong-source", "wrong-decision", "not-yet-valid", "expired", "bad-signature", "untrusted"))
def test_deployment_registry_refuses_each_approval_artifact_failure(tmp_path: Path, case: str) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    activation = json.loads(paths["activation"].read_text())
    if case == "unknown":
        activation["approval_digests"][0]["approval_digest"] = digest("unknown-approval")
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "duplicate":
        activation["approval_digests"][1]["approval_digest"] = activation["approval_digests"][0]["approval_digest"]
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "wrong-role":
        activation["approval_digests"][0]["role"] = "product"
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "wrong-order":
        activation["approval_digests"][0], activation["approval_digests"][1] = activation["approval_digests"][1], activation["approval_digests"][0]
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    elif case == "wrong-workspace": _replace_approval(approvals, activation, keys, 0, workspace_ref="workspace:wrong")
    elif case == "wrong-source": _replace_approval(approvals, activation, keys, 0, source_ref="wrong-source")
    elif case == "wrong-decision": _replace_approval(approvals, activation, keys, 0, decision_digest=digest("wrong-decision"))
    elif case == "not-yet-valid": _replace_approval(approvals, activation, keys, 0, issued_at="2026-04-01T00:00:01Z", expires_at="2026-04-15T00:00:00Z")
    elif case == "expired": _replace_approval(approvals, activation, keys, 0, expires_at="2026-03-31T23:59:59Z")
    elif case == "bad-signature":
        reference = activation["approval_digests"][0]
        old_digest = reference["approval_digest"]
        sealed = dict(approvals.pop(old_digest))
        sealed["signature"] = b64encode(b"x" * 64).decode("ascii")
        new_digest = sha256(canonical_bytes(sealed)).hexdigest()
        approvals[new_digest] = sealed
        reference["approval_digest"] = new_digest
        _reseal(activation, digest_field="activation_digest", key=keys[("signer:activation", "key:activation")], domain=_ACTIVATION_DOMAIN)
    else:
        _replace_approval(approvals, activation, keys, 0, signer_ref="signer:untrusted")
    # Approval references are part of the signed activation digest.  Rebind the
    # signed consent fixture too, so these cases exercise the deployment
    # approval registry rather than the earlier application binding gate.
    consent = json.loads(paths["consent"].read_text())
    consent["activation_digest"] = activation["activation_digest"]
    _reseal(consent, digest_field="receipt_digest", key=keys[("signer:consent", "key:consent")], domain=_CONSENT_DOMAIN)
    _write(paths["activation"], activation)
    _write(paths["consent"], consent)
    out = tmp_path / f"approval-{case}.json"
    authority = _Authority(keys, approvals, paths["retention_end"])
    assert script["run_with_authority"](_argv(paths, out), authority=authority) == 2
    assert not out.exists()
    if case == "bad-signature":
        assert _APPROVAL_DOMAIN in authority.signature_verification_domains


@pytest.mark.parametrize("case", ("wrong-mode", "no-import", "missing-restore", "missing-recall", "bad-digest"))
def test_conservation_evidence_is_revalidated_not_trusted_by_path(tmp_path: Path, case: str) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    conservation = json.loads(paths["conservation"].read_text())
    if case == "wrong-mode":
        conservation["verification_mode"] = "CONSERVATION_ONLY"
        conservation["recall_sample_digest"] = conservation["isolated_restore_target_digest"] = conservation["deterministic_recall_digest"] = None
    elif case == "no-import": conservation["result"]["no_import"] = True
    elif case == "missing-restore": conservation["isolated_restore_target_digest"] = None
    elif case == "missing-recall": conservation["deterministic_recall_digest"] = None
    else: conservation["receipt_sha256"] = "0" * 64
    if case != "bad-digest":
        body = {key: value for key, value in conservation.items() if key != "receipt_sha256"}
        conservation["receipt_sha256"] = sha256(canonical_bytes(body)).hexdigest()
    _write(paths["conservation"], conservation)
    out = tmp_path / f"conservation-{case}.json"
    assert script["run_with_authority"](_argv(paths, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 2
    assert not out.exists()
