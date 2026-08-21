"""Live me-wiki discovery evidence is body-free and non-serving."""
from __future__ import annotations

import json
from pathlib import Path

_MANIFEST = (
    Path(__file__).resolve().parents[2]
    / "artifacts/product-release/second-brain-v1/evidence/me-wiki-discovery-manifest-v1.json"
)


def test_me_wiki_discovery_manifest_is_body_free_and_non_serving() -> None:
    payload = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert payload["body_reads"] == "0"
    assert payload["source_name"] == "me-wiki"
    assert payload["source_root"] == "/Volumes/DevSpace/me-wiki"
    assert payload["entry_count"].isdigit()
    assert isinstance(payload["entry_count"], str)
    assert int(payload["entry_count"]) == len(payload["entries"])
    assert "serving" not in json.dumps(payload)
    for entry in payload["entries"]:
        assert "body" not in entry
        assert "content" not in entry
        assert isinstance(entry["path_digest"], str)
        assert len(entry["path_digest"]) == 64
