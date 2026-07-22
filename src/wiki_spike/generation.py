"""Candidate generation build (SUB-05, v3.3 §4-5, §4-7, §5-1).

Strict order (fixes N2): render pages -> build citation index -> compute inline
digests -> assemble descriptor -> generation_id = H(descriptor) -> sign ->
candidate commit -> retention anchor.

No self-reference (fixes N1/round-4): the descriptor contains NO commit oid and NO
generation_id; generation_id is derived from the descriptor alone. The commit
contains the manifest, but the manifest never contains its own commit oid. The
commit oid lives only in the retention ref name->oid mapping and (later) the DB.
"""
from __future__ import annotations

from dataclasses import dataclass

from .assembler import build_citation_index, build_snapshot, render_pages, wiki_files_root
from .canonical import canonical_bytes
from .claims import CompiledClaim
from .gitrepo import GitRepo
from .hashing import canonical_hash, sha256_hex
from .signing import Keyring

ENGINE_VERSIONS = {
    # exact LLM ids are still PENDING (selection eval); the spike is deterministic.
    "parser": "spike-parser@0",
    "chunker": "spike-chunker@0",
    "schema": "1",
    "trust_policy": "spike-policy@0",
    "prompt_hash": "n/a-deterministic",
    "engine_code_commit": "spike",
    "container_image_digest": "spike",
    "extraction_model_id": "MOCK-DETERMINISTIC",  # not a real model id
    "verification_model_id": "MOCK-DETERMINISTIC",
    "render_model_id": "DETERMINISTIC-ASSEMBLER",
    "embedding_version": "n/a",
}


@dataclass
class CandidateResult:
    generation_id: str
    commit_oid: str
    retention_ref: str
    descriptor: dict
    manifest: dict
    wiki_files_root: str
    citation_index_digest: str
    knowledge_snapshot_digest: str = ""


class GenerationBuilder:
    def __init__(self, repo: GitRepo, keyring: Keyring, key_id: str, profile: str = "phase1") -> None:
        self.repo = repo
        self.keyring = keyring
        self.key_id = key_id
        self.profile = profile

    def build_candidate(
        self,
        accepted: list[CompiledClaim],
        parent_generation_id: str | None,
        source_snapshot_hash: str,
        accepted_claim_set_root: str,
        *,
        changeset_binding: dict | None = None,
    ) -> CandidateResult:
        # ---- N2 order: render -> citation -> snapshot -> digests --------- #
        pages = render_pages(accepted)
        citation = build_citation_index(accepted)
        snapshot = build_snapshot(accepted)
        wroot = wiki_files_root(pages)
        cdigest = sha256_hex(citation)
        sdigest = sha256_hex(snapshot)

        descriptor = {
            "schema_version": "1",
            "parent_generation_id": parent_generation_id or "",
            "source_snapshot_hash": source_snapshot_hash,
            "accepted_claim_set_root": accepted_claim_set_root,
            "inline_artifacts": {
                "wiki_files_root": wroot,
                "citation_index_digest": cdigest,
                "knowledge_snapshot_digest": sdigest,
            },
            "publication_profile": self.profile,
            "engine_versions": ENGINE_VERSIONS,
        }
        if changeset_binding is not None:
            descriptor["accepted_changeset"] = changeset_binding
        generation_id = canonical_hash(descriptor)  # acyclic: descriptor has no self-ref
        signature = self.keyring.sign(self.key_id, generation_id.encode("utf-8")).hex()
        manifest = {
            "descriptor": descriptor,
            "generation_id": generation_id,
            "signer_key_id": self.key_id,
            "signature": signature,
        }
        outbox_event = {
            "event_id": sha256_hex(f"ready:{generation_id}".encode()),
            "generation_id": generation_id,
            "event_type": "generation_ready_for_index",
            "required_read_models": ["wiki_files", "citation_index"],
        }

        # ---- commit tree (pages + citation + snapshot + manifest + outbox) - #
        files = dict(pages)
        files["citation_index/index.json"] = citation
        files["knowledge/snapshot.json"] = snapshot
        files[f"manifest/{generation_id}.json"] = canonical_bytes(manifest)
        files[f"outbox/{generation_id}.json"] = canonical_bytes(outbox_event)
        tree = self.repo.write_tree_from_files(files)

        parent_commit = None
        if parent_generation_id:
            parent_commit = self.repo.read_ref(f"refs/wiki/generations/{parent_generation_id}")
            if parent_commit is None:
                raise ValueError(f"parent generation not found: {parent_generation_id}")
        commit_oid = self.repo.commit_tree(tree, f"gen {generation_id}", parent=parent_commit)

        # ---- N3: mandatory retention anchor (keeps commit reachable) ------ #
        # Create-only: a generation_id maps to exactly one commit (immutable). If it
        # already exists pointing elsewhere, that is a hard error.
        retention_ref = f"refs/wiki/generations/{generation_id}"
        existing = self.repo.read_ref(retention_ref)
        if existing is None:
            self.repo.create_ref_only(retention_ref, commit_oid)
        elif existing != commit_oid:
            raise ValueError(
                f"generation ref {retention_ref} already points to {existing}, refusing to move"
            )

        return CandidateResult(
            generation_id=generation_id,
            commit_oid=commit_oid,
            retention_ref=retention_ref,
            descriptor=descriptor,
            manifest=manifest,
            wiki_files_root=wroot,
            citation_index_digest=cdigest,
            knowledge_snapshot_digest=sdigest,
        )

    def verify_manifest(self, commit_oid: str, generation_id: str) -> bool:
        """Verify signature AND that the commit's actual content matches the descriptor.

        Binds the signature to the real wiki/** files and citation index (not just the
        descriptor hash), so a tampered commit with a copied manifest fails.
        """
        import json

        from .assembler import wiki_files_root
        from .hashing import sha256_hex

        try:
            raw = self.repo.cat_file(f"{commit_oid}:manifest/{generation_id}.json")
        except Exception:
            return False
        manifest = json.loads(raw)
        if manifest.get("generation_id") != generation_id:
            return False
        descriptor = manifest.get("descriptor", {})
        if canonical_hash(descriptor) != generation_id:
            return False
        if not self.keyring.verify(
            manifest["signer_key_id"], generation_id.encode("utf-8"), bytes.fromhex(manifest["signature"])
        ):
            return False

        # --- content binding: re-hash the real artifacts from the commit --- #
        inline = descriptor.get("inline_artifacts", {})
        all_paths = set(self.repo.ls_tree(commit_oid))
        wiki_paths = [p for p in all_paths if p.startswith("wiki/")]
        # File allowlist: reject any file outside the expected set (#3.5).
        expected = set(wiki_paths) | {
            "citation_index/index.json", "knowledge/snapshot.json",
            f"manifest/{generation_id}.json", f"outbox/{generation_id}.json",
        }
        if all_paths != expected:
            return False
        pages = {p: self.repo.cat_file(f"{commit_oid}:{p}") for p in wiki_paths}
        if wiki_files_root(pages) != inline.get("wiki_files_root"):
            return False
        try:
            citation = self.repo.cat_file(f"{commit_oid}:citation_index/index.json")
            snapshot = self.repo.cat_file(f"{commit_oid}:knowledge/snapshot.json")
        except Exception:
            return False
        if sha256_hex(citation) != inline.get("citation_index_digest"):
            return False
        if sha256_hex(snapshot) != inline.get("knowledge_snapshot_digest"):
            return False
        try:
            from .assembler import build_citation_index, parse_snapshot, render_pages
            reconstructed = parse_snapshot(snapshot)
        except Exception:
            return False
        if render_pages(reconstructed) != pages:
            return False
        if build_citation_index(reconstructed) != citation:
            return False
        return True

    def verify_release(self, release_commit_oid: str, generation_id: str) -> bool:
        """Verify the signed ReleaseManifest and its binding to the candidate."""
        import json

        try:
            raw = self.repo.cat_file(f"{release_commit_oid}:release/{generation_id}.json")
        except Exception:
            return False
        rm = json.loads(raw)
        if rm.get("generation_id") != generation_id:
            return False
        sig = rm.get("signature")
        signer = rm.get("signer_key_id")
        if not sig or not signer:
            return False
        body = {k: rm[k] for k in rm if k != "signature"}
        # Release uses a SEPARATE signing domain.
        return self.keyring.verify_domain(
            signer, "wiki.release.v1", canonical_hash(body).encode("utf-8"), bytes.fromhex(sig)
        )
