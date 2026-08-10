from __future__ import annotations

from base64 import b64encode
from dataclasses import replace
import json
import os
import subprocess
import sys
from pathlib import Path
import runpy

import pytest

from test_decommission_certificate import _Authority, _argv, _files, _signed, _CERTIFICATE_DOMAIN
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import DecommissionCertificateV1


CLI = Path(__file__).parents[2] / "scripts" / "second_brain_decommission_certificate.py"


def test_public_cli_has_no_trust_surface_and_refuses_before_input_io(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    out = tmp_path / "out.json"
    command = [sys.executable, str(CLI), "verify", "--activation", str(missing), "--retention-end", "2026-04-01T00:00:00Z", "--decision", str(missing), "--conservation", str(missing), "--allowlist-digest", "a" * 64, "--consent-transfer", str(missing), "--out", str(out)]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 2
    assert result.stderr.strip() == "FAIL: DEPLOYMENT_DECOMMISSION_AUTHORITY_ABSENT"
    assert not out.exists()
    help_result = subprocess.run([sys.executable, str(CLI), "--help"], text=True, capture_output=True, check=False)
    assert help_result.returncode == 0
    for forbidden in ("--key", "--registry", "--clock", "--signer", "--public-key"):
        assert forbidden not in help_result.stdout


def test_internal_argparse_refuses_with_rc_two_instead_of_raising(tmp_path: Path, capsys) -> None:
    keys, approvals, _, _ = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    assert script["run_with_authority"](["unknown"], authority=_Authority(keys, approvals, "2026-04-01T00:00:00Z")) == 2
    assert "AUTHORIZED_DECOMMISSION_REJECTED" not in capsys.readouterr().err


def test_missing_or_failing_certificate_verifier_never_publishes_or_leaks_secrets(tmp_path: Path, capsys) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))

    class MissingVerifier:
        def issue_decommission_certificate(self, *args, **kwargs):
            raise AssertionError("must not be called")

    class Exploding:
        def issue_decommission_certificate(self, *args, **kwargs):
            raise RuntimeError("SECRET_MARKER_MUST_NOT_ESCAPE")
        def verify_issued_decommission_certificate(self, *args, **kwargs):
            return True

    class VerifyFalse(_Authority):
        def verify_issued_decommission_certificate(self, *args, **kwargs):
            return False

    class VerifyExploding(_Authority):
        def verify_issued_decommission_certificate(self, *args, **kwargs):
            raise RuntimeError("VERIFY_SECRET_MARKER_MUST_NOT_ESCAPE")

    assert script["run_with_authority"](_argv(paths, tmp_path / "missing.json"), authority=MissingVerifier()) == 2
    assert script["run_with_authority"](_argv(paths, tmp_path / "secret.json"), authority=Exploding()) == 2
    assert script["run_with_authority"](_argv(paths, tmp_path / "verify-false.json"), authority=VerifyFalse(keys, approvals, paths["retention_end"])) == 2
    assert script["run_with_authority"](_argv(paths, tmp_path / "verify-secret.json"), authority=VerifyExploding(keys, approvals, paths["retention_end"])) == 2
    captured = capsys.readouterr()
    assert "SECRET_MARKER_MUST_NOT_ESCAPE" not in captured.out + captured.err
    assert "VERIFY_SECRET_MARKER_MUST_NOT_ESCAPE" not in captured.out + captured.err
    assert captured.err.count("FAIL: AUTHORIZED_DECOMMISSION_REJECTED") == 4


def test_tampered_or_untrusted_returned_certificate_cannot_be_published(tmp_path: Path) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))

    class BadCertificate(_Authority):
        def issue_decommission_certificate(self, *args, **kwargs):
            certificate = super().issue_decommission_certificate(*args, **kwargs)
            return replace(certificate, signature=b64encode(b"x" * 64).decode("ascii"))

    class RawMapping(_Authority):
        def issue_decommission_certificate(self, *args, **kwargs):
            return super().issue_decommission_certificate(*args, **kwargs).to_mapping()

    for authority, name in ((BadCertificate(keys, approvals, paths["retention_end"]), "bad-signature"), (RawMapping(keys, approvals, paths["retention_end"]), "raw-mapping")):
        out = tmp_path / f"{name}.json"
        assert script["run_with_authority"](_argv(paths, out), authority=authority) == 2
        assert not out.exists()


@pytest.mark.parametrize("case", ("mismatched-request", "before-retention", "consent-expiry", "destructive", "bad-self-digest", "untrusted-signer"))
def test_malicious_but_typed_certificate_variants_cannot_be_published(tmp_path: Path, case: str) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))

    class Malicious(_Authority):
        def issue_decommission_certificate(self, *args, **kwargs):
            certificate = super().issue_decommission_certificate(*args, **kwargs)
            document = certificate.to_mapping()
            if case == "mismatched-request":
                document["request"]["source_ref"] = "wrong-source"
                request_body = {key: value for key, value in document["request"].items() if key != "request_digest"}
                document["request"]["request_digest"] = sha256(canonical_bytes(request_body)).hexdigest()
                document["request_digest"] = document["request"]["request_digest"]
            elif case == "before-retention": document["verified_at"] = "2026-03-31T23:59:59Z"
            elif case == "consent-expiry": document["verified_at"] = "2026-05-01T00:00:00Z"
            elif case == "destructive": return replace(certificate, destructive_action_authorized=True)
            elif case == "bad-self-digest":
                return replace(certificate, certificate_digest="0" * 64)
            else: document["signer_ref"] = "signer:untrusted"
            body = {key: value for key, value in document.items() if key not in {"certificate_digest", "signature"}}
            document["certificate_digest"] = sha256(canonical_bytes(body)).hexdigest()
            document["signature"] = _signed(keys[("signer:certificate", "key:certificate")], _CERTIFICATE_DOMAIN, body)
            return DecommissionCertificateV1.from_mapping(document)

    out = tmp_path / f"malicious-{case}.json"
    assert script["run_with_authority"](_argv(paths, out), authority=Malicious(keys, approvals, paths["retention_end"])) == 2
    assert not out.exists()


@pytest.mark.parametrize("kind", ("duplicate-json", "symlink", "hardlink", "oversize", "noncanonical", "output-collision"))
def test_unsafe_input_or_output_paths_are_rejected_without_input_mutation(tmp_path: Path, kind: str) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    activation = paths["activation"]
    original = activation.read_bytes()
    out = tmp_path / f"{kind}.out"
    altered = dict(paths)
    if kind == "duplicate-json":
        activation.write_bytes(b'{"x":"1","x":"2"}')
    elif kind == "symlink":
        link = tmp_path / "activation-link.json"; link.symlink_to(activation); altered["activation"] = link
    elif kind == "hardlink":
        hard = tmp_path / "activation-hard.json"; os.link(activation, hard); altered["activation"] = hard
    elif kind == "oversize":
        activation.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    elif kind == "noncanonical":
        altered["activation"] = str(activation.parent) + "/./activation.json"
    else:
        out.write_bytes(b"already-present")
    assert script["run_with_authority"](_argv(altered, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 2
    assert (not out.exists()) if kind != "output-collision" else out.read_bytes() == b"already-present"
    if kind in {"duplicate-json", "oversize"}:
        assert activation.read_bytes() != original
    else:
        assert activation.read_bytes() == original


def test_atomic_fsync_faults_leave_no_certificate(tmp_path: Path, monkeypatch) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    real_fsync = script["os"].fsync
    for name, failure_at in (("file", 1), ("directory", 2)):
        calls = 0
        def fail_at(descriptor):
            nonlocal calls
            calls += 1
            if calls == failure_at:
                raise OSError("fault")
            return real_fsync(descriptor)
        monkeypatch.setattr(script["os"], "fsync", fail_at)
        out = tmp_path / f"{name}.json"
        assert script["run_with_authority"](_argv(paths, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 2
        assert not out.exists()
        monkeypatch.setattr(script["os"], "fsync", real_fsync)


def test_post_commit_private_temp_cleanup_failure_preserves_valid_certificate(tmp_path: Path, monkeypatch) -> None:
    keys, approvals, _, paths = _files(tmp_path)
    script = runpy.run_path(str(CLI))
    real_unlink = script["os"].unlink

    def fail_only_private_temp(path, *args, **kwargs):
        if Path(path).name.startswith(".cleanup.") and str(path).endswith(".tmp"):
            raise OSError("private cleanup fault")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(script["os"], "unlink", fail_only_private_temp)
    out = tmp_path / "cleanup.json"
    assert script["run_with_authority"](_argv(paths, out), authority=_Authority(keys, approvals, paths["retention_end"])) == 0
    assert DecommissionCertificateV1.from_mapping(json.loads(out.read_text())).state == "ROLLBACK_CLOSED"
    assert any(item.name.startswith(".cleanup.") and item.name.endswith(".tmp") for item in tmp_path.iterdir())
