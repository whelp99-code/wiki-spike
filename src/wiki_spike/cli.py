"""CLI adapter (Phase 1a + 1b + SUB-07, v3.3 §13).

Phase 1a primitives (no publication):
  receive <path>          -> CAS + manifest
  compile <source_id>     -> Claim IR

Integrated pipeline (Phase 1a -> 1b, under a single-publisher lease):
  ingest  <path>          -> receive + compile + publish
  search  <term>          -> staleness-aware query
  mirror                  -> relay outbox to the remote mirror
  log                     -> publication pointer + generation history

Exit codes: 0 ok · 3 quarantined · 4 idempotent no-op · 5 zero claims ·
            7 lease held by another publisher · 66 path not found · 1 other.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cas import ContentAddressedStore
from .claims import DeterministicMockExtractor
from .controlplane import LeaseError
from .ingest import IngestService
from .workspace import Workspace


def _phase1a_service(root: Path) -> IngestService:
    return IngestService(ContentAddressedStore(root / "cas"), DeterministicMockExtractor())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wiki", description="wiki-spike Phase 1a/1b/SUB-07")
    parser.add_argument("--root", default=".wiki-spike")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("receive"); p.add_argument("path")
    p = sub.add_parser("compile"); p.add_argument("source_id")
    p = sub.add_parser("status"); p.add_argument("source_id")
    p = sub.add_parser("ingest"); p.add_argument("path")
    p = sub.add_parser("search"); p.add_argument("term")
    p = sub.add_parser("admin-revoke"); p.add_argument("claim_id"); p.add_argument("--reason", default="admin")
    sub.add_parser("mirror")
    sub.add_parser("log")

    args = parser.parse_args(argv)
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)

    # --- Phase 1a primitives (no publication surface) ---
    if args.cmd in ("receive", "compile", "status"):
        svc = _phase1a_service(root)
        if args.cmd == "receive":
            path = Path(args.path)
            if not path.exists():
                print(f"path not found: {path}", file=sys.stderr)
                return 66
            res = svc.receive(path)
            print(f"source_id={res.source_id}\nstatus={res.status}")
            return 4 if res.idempotent else 0
        if args.cmd == "compile":
            res = svc.compile(args.source_id)
            for c in res.claims:
                print(f"{c.identity.claim_id[:12]}  {c.identity.subject_id} "
                      f"{c.identity.predicate_id} {c.identity.obj} [{c.identity.polarity}]")
            print(f"claims={len(res.claims)} status={res.status}")
            return 0 if res.claims else 5
        if args.cmd == "status":
            try:
                print(svc.manifest(args.source_id).status)
                return 0
            except KeyError:
                # Phase 1a keeps manifest state in memory only; a fresh process has none.
                print("unknown (no persistent manifest in phase 1a)", file=sys.stderr)
                return 1

    # --- Integrated pipeline + SUB-07 ---
    ws = Workspace(root)
    try:
        if args.cmd == "ingest":
            path = Path(args.path)
            if not path.exists():
                print(f"path not found: {path}", file=sys.stderr)
                return 66
            try:
                r = ws.ingest_and_publish(path)
            except LeaseError as e:
                print(str(e), file=sys.stderr)
                return 7
            print(f"source_id={r.source_id}")
            print(f"new_claims={r.new_claims}  revokes={r.revokes}")
            if r.quarantined:
                print("result=quarantined (source proposed REVOKE; not published, pointer unchanged)")
                ptr = ws.cp.current_pointer()
                print(f"pointer={ptr[:12] if ptr else None}")
                return 3
            if r.publish.noop:
                print("result=noop (nothing new; pointer unchanged)")
                ptr = ws.cp.current_pointer()
                print(f"pointer={ptr[:12] if ptr else None}")
                return 0
            print(f"generation={r.publish.generation_id[:12]}  "
                  f"candidate={r.publish.candidate_commit_oid[:12]}  attempts={r.publish.attempts}")
            print(f"pointer={ws.cp.current_pointer()[:12]}")
            return 0

        if args.cmd == "search":
            resp = ws.query(args.term)
            if resp.disabled:
                print("search disabled: generation lag exceeded")
                return 0
            tag = " (stale)" if resp.stale else ""
            iw = resp.indexed_generation_id[:12] if resp.indexed_generation_id else "-"
            cw = resp.current_wiki_generation_id[:12] if resp.current_wiki_generation_id else "-"
            print(f"indexed_gen={iw} current_wiki_gen={cw}{tag}")
            for h in resp.hits:
                print(f"  {h.claim_id}  {h.subject} {h.predicate} {h.obj}")
            print(f"hits={len(resp.hits)}")
            return 0

        if args.cmd == "admin-revoke":
            res = ws.admin_revoke([args.claim_id], reason=args.reason)
            if res.noop:
                print("result=noop (claim not present)")
            else:
                print(f"revoked; generation={res.generation_id[:12]} pointer={ws.cp.current_pointer()[:12]}")
            return 0

        if args.cmd == "mirror":
            n = ws.mirror_now()
            print(f"mirrored_events={n}")
            return 0

        if args.cmd == "log":
            ptr = ws.cp.current_pointer()
            print(f"current_pointer={ptr[:12] if ptr else None}")
            rows = ws.cp.con.execute(
                "SELECT seq, generation_id, state FROM generation ORDER BY seq"
            ).fetchall()
            for seq, gid, state in rows:
                print(f"  G{seq} {gid[:12]} {state}")
            return 0
    finally:
        ws.close()

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
