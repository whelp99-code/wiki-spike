#!/usr/bin/env python3
"""Strictly import one named immutable encrypted-lifecycle bundle archive."""
from __future__ import annotations
import argparse, hashlib, json, re, stat, sys, tarfile, unicodedata
from pathlib import Path
from typing import Any, Mapping

ENVELOPE_SCHEMA="wiki-artifact-bundle-envelope-v1"; MANIFEST_SCHEMA="wiki-artifact-bundle-manifest-v1"; ENVELOPE_ENTRY_PATH="artifact-envelope.json"; MANIFEST_ENTRY_PATH="bundle-manifest.json"
KIND_PAYLOADS={"SQLCIPHER_FEASIBILITY":("payload/sqlcipher-feasibility.json",),"GATE1_DECISION":("payload/gate1-decision.json","payload/macos/sqlcipher-feasibility.json","payload/ubuntu/import-receipt.json","payload/vector-validation.json"),"CONFORMANCE_PRE_CANARY":("payload/conformance-pre-canary.json",),"CANARY_24H":("payload/rollout-evidence.json",)}
PLATFORMS=frozenset(("github-hosted/ubuntu-24.04/x86_64","self-hosted/macos-26/arm64/wiki-gate1-workstation","self-hosted/macos-26/arm64/wiki-conformance-workstation","self-hosted/macos-26/arm64/wiki-canary-workstation"))
HEX64=re.compile(r"^[0-9a-f]{64}$"); SHA40=re.compile(r"^[0-9a-f]{40}$"); DECIMAL=re.compile(r"^(0|[1-9][0-9]*)$"); REPOSITORY=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"); TIMESTAMP=re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

class BundleImportError(Exception):
 def __init__(self, code:str, message:str): super().__init__(f"{code}: {message}"); self.code=code; self.message=message

def fail(code:str, message:str)->None: raise BundleImportError(code,message)
def sha256_hex(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def canonical_bytes(value:Mapping[str,Any])->bytes:
 def norm(v:Any,path:str)->Any:
  if v is None or isinstance(v,bool): return v
  if isinstance(v,str): return unicodedata.normalize("NFC",v)
  if isinstance(v,(int,float)): fail("RAW_NUMERIC_TOKEN",f"raw numeric token at {path}")
  if isinstance(v,list): return [norm(x,f"{path}[{i}]") for i,x in enumerate(v)]
  if isinstance(v,Mapping):
   out={}
   for k,x in v.items():
    if not isinstance(k,str): fail("NON_STRING_KEY",f"non-string key at {path}")
    k=unicodedata.normalize("NFC",k)
    if k in out: fail("DUPLICATE_NFC_KEY",f"duplicate NFC key at {path}")
    out[k]=norm(x,f"{path}.{k}")
   return {k:out[k] for k in sorted(out)}
  fail("UNSUPPORTED_VALUE",f"unsupported value at {path}")
 return json.dumps(norm(value,"$"),ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def reject_duplicates(pairs:list[tuple[str,Any]])->dict[str,Any]:
 out={}
 for k,v in pairs:
  if k in out: fail("DUPLICATE_JSON_KEY",f"duplicate key {k!r}")
  out[k]=v
 return out
def strict_document(raw:bytes, label:str)->dict[str,Any]:
 if raw.startswith(b"\xef\xbb\xbf"): fail("DOCUMENT_BOM",f"{label} has UTF-8 BOM")
 try: value=json.loads(raw.decode("utf-8"),object_pairs_hook=reject_duplicates)
 except BundleImportError: raise
 except (UnicodeDecodeError,json.JSONDecodeError) as exc: fail("DOCUMENT_INVALID_JSON",f"{label}: {exc}")
 if not isinstance(value,dict): fail("DOCUMENT_NOT_OBJECT",label)
 if canonical_bytes(value)!=raw: fail("DOCUMENT_NOT_CANONICAL",label)
 return value
def validate_path(path:Any, code:str="INVALID_PATH")->str:
 if not isinstance(path,str) or not path or len(path.encode())>240 or path!=unicodedata.normalize("NFC",path): fail(code,"path must be NFC UTF-8")
 if "\\" in path or path.startswith("/") or "//" in path or any(ord(c)<32 or ord(c)==127 for c in path) or any(x in ("",".","..") for x in path.split("/")): fail(code,f"invalid path {path!r}")
 return path
def load_archive(archive:Path)->dict[str,bytes]:
 if not archive.is_file() or archive.is_symlink() or archive.suffix!=".tar": fail("ARCHIVE_REQUIRED","input must be one explicitly named regular .tar archive")
 files={}
 try:
  with tarfile.open(archive,"r") as tar:
   for member in tar.getmembers():
    name=validate_path(member.name,"ARCHIVE_PATH_INVALID")
    if member.isdir() or not member.isreg() or member.issym() or member.islnk() or member.isdev(): fail("ARCHIVE_MEMBER_TYPE",f"non-regular member {name!r}")
    if stat.S_IMODE(member.mode)!=0o644: fail("ARCHIVE_MEMBER_MODE",f"member {name!r} mode is not 0644")
    if name in files: fail("ARCHIVE_DUPLICATE_PATH",name)
    source=tar.extractfile(member)
    if source is None: fail("ARCHIVE_MEMBER_UNREADABLE",name)
    files[name]=source.read()
 except (tarfile.TarError,OSError) as exc: fail("ARCHIVE_INVALID",str(exc))
 return files
def validate_envelope(envelope:dict[str,Any])->None:
 required={"schema","artifact_kind","repository","producer_commit","contract_digest","toolchain_lock_digest","workflow_file_digest","workflow_run_id","workflow_run_attempt","platform","artifact_name","payload_paths","payload_sha256","bundle_sha256","produced_at"}
 if set(envelope)!=required: fail("ENVELOPE_KEYS_INVALID","envelope must have exactly the closed 15-field wire")
 if envelope["schema"]!=ENVELOPE_SCHEMA or envelope["artifact_kind"] not in KIND_PAYLOADS: fail("ENVELOPE_SCHEMA_OR_KIND", "invalid schema or artifact kind")
 if not REPOSITORY.fullmatch(envelope["repository"]) or envelope["repository"]!=unicodedata.normalize("NFC",envelope["repository"]): fail("ENVELOPE_REPOSITORY_INVALID","invalid repository")
 if not SHA40.fullmatch(envelope["producer_commit"]): fail("ENVELOPE_COMMIT_INVALID","producer commit must be 40 lowercase hex")
 for field in ("contract_digest","toolchain_lock_digest","workflow_file_digest","bundle_sha256"):
  if not HEX64.fullmatch(envelope[field]): fail("ENVELOPE_DIGEST_INVALID",field)
 for field in ("workflow_run_id","workflow_run_attempt"):
  if not isinstance(envelope[field],str) or not DECIMAL.fullmatch(envelope[field]): fail("ENVELOPE_RUN_INVALID",field)
 if envelope["platform"] not in PLATFORMS or not TIMESTAMP.fullmatch(envelope["produced_at"]): fail("ENVELOPE_PLATFORM_OR_TIME_INVALID","invalid platform or timestamp")
 if not isinstance(envelope["payload_paths"],list) or not isinstance(envelope["payload_sha256"],list): fail("ENVELOPE_PAYLOAD_INVALID","payload lists required")
 if tuple(envelope["payload_paths"])!=KIND_PAYLOADS[envelope["artifact_kind"]] or len(envelope["payload_sha256"])!=len(envelope["payload_paths"]): fail("ENVELOPE_PAYLOAD_SET_INVALID","payload set is not exact for kind")
 for path in envelope["payload_paths"]: validate_path(path,"ENVELOPE_PAYLOAD_PATH_INVALID")
 if len(set(envelope["payload_paths"]))!=len(envelope["payload_paths"]) or any(not isinstance(x,str) or not HEX64.fullmatch(x) for x in envelope["payload_sha256"]): fail("ENVELOPE_PAYLOAD_INVALID","invalid payload list")
def import_bundle(archive:Path, *, expected:Mapping[str,Any]|None=None)->dict[str,Any]:
 files=load_archive(archive)
 if MANIFEST_ENTRY_PATH not in files: fail("MANIFEST_MISSING",MANIFEST_ENTRY_PATH)
 if ENVELOPE_ENTRY_PATH not in files: fail("ENVELOPE_MISSING",ENVELOPE_ENTRY_PATH)
 manifest=strict_document(files[MANIFEST_ENTRY_PATH],"manifest")
 if set(manifest)!={"schema","entries"} or manifest["schema"]!=MANIFEST_SCHEMA or not isinstance(manifest["entries"],list): fail("MANIFEST_INVALID","closed manifest wire required")
 envelope=strict_document(files[ENVELOPE_ENTRY_PATH],"envelope"); validate_envelope(envelope)
 entries=manifest["entries"]; by_path={}
 for entry in entries:
  if not isinstance(entry,dict) or set(entry)!={"path","sha256","size"}: fail("MANIFEST_ENTRY_INVALID","closed entry wire required")
  path=validate_path(entry.get("path"),"MANIFEST_PATH_INVALID")
  if path in by_path or not isinstance(entry.get("sha256"),str) or not HEX64.fullmatch(entry["sha256"]) or not isinstance(entry.get("size"),str) or not DECIMAL.fullmatch(entry["size"]): fail("MANIFEST_ENTRY_INVALID",path)
  by_path[path]=entry
 if [entry["path"] for entry in entries] != sorted(by_path,key=lambda p:p.encode()): fail("MANIFEST_ORDER_INVALID","entries must sort by raw UTF-8 path")
 expected_files={ENVELOPE_ENTRY_PATH,*envelope["payload_paths"],MANIFEST_ENTRY_PATH}
 if set(files)!=expected_files or set(by_path)!=(expected_files-{MANIFEST_ENTRY_PATH}): fail("ARCHIVE_FILE_SET_INVALID","archive and manifest file sets must be exact")
 projected=dict(envelope,artifact_name="",bundle_sha256=""); projected_bytes=canonical_bytes(projected); envelope_entry=by_path[ENVELOPE_ENTRY_PATH]
 if envelope_entry["sha256"]!=sha256_hex(projected_bytes) or envelope_entry["size"]!=str(len(projected_bytes)): fail("ENVELOPE_PROJECTION_MISMATCH","projected envelope manifest entry mismatch")
 digest=sha256_hex(files[MANIFEST_ENTRY_PATH]); kind=envelope["artifact_kind"]; derived=f"encrypted-lifecycle-{kind.lower().replace('_','-')}-{envelope['workflow_run_id']}-{envelope['workflow_run_attempt']}-{digest[:16]}"
 if envelope["bundle_sha256"]!=digest or envelope["artifact_name"]!=derived or archive.name!=f"{derived}.tar": fail("ARTIFACT_IDENTITY_MISMATCH","stored and archive artifact identity must be exact")
 for path,digest_value in zip(envelope["payload_paths"],envelope["payload_sha256"]):
  raw=files[path]; entry=by_path[path]
  if sha256_hex(raw)!=digest_value or entry["sha256"]!=digest_value or entry["size"]!=str(len(raw)): fail("PAYLOAD_DIGEST_MISMATCH",path)
  strict_document(raw,path)
 if expected is not None:
  required=("repository","artifact_kind","platform","producer_commit","contract_digest","toolchain_lock_digest","workflow_file_digest","workflow_run_id","workflow_run_attempt","artifact_name","bundle_sha256","payload_paths","payload_sha256","source_run_url")
  if set(expected)!=set(required): fail("EXPECTED_TUPLE_INVALID","expected tuple must use the closed receipt fields")
  for field in required:
   if field=="source_run_url": continue
   if envelope.get(field)!=expected[field]: fail("EXPECTED_TUPLE_MISMATCH",field)
 receipt={field:envelope[field] for field in ("repository","artifact_kind","platform","producer_commit","contract_digest","toolchain_lock_digest","workflow_file_digest","workflow_run_id","workflow_run_attempt","artifact_name")}; receipt.update(bundle_sha256=digest,payload_paths=envelope["payload_paths"],payload_sha256=envelope["payload_sha256"],source_run_url=(expected or {}).get("source_run_url",""),verified=True)
 return receipt
def main(argv:list[str]|None=None)->int:
 parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",required=True); parser.add_argument("--output",required=True); args=parser.parse_args(argv)
 try: result=import_bundle(Path(args.input))
 except BundleImportError as exc: print(f"REJECTED [{exc.code}] {exc.message}",file=sys.stderr); return 1
 output=Path(args.output); output.mkdir(parents=True,exist_ok=True); files=load_archive(Path(args.input))
 for path in result["payload_paths"]:
  dest=output/path; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(files[path])
 (output/"import-receipt.json").write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8"); print(f"imported bundle artifact_name={result['artifact_name']} bundle_sha256={result['bundle_sha256']}"); return 0
if __name__=="__main__": raise SystemExit(main())
