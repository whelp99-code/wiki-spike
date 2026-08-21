"""Packaged StateDeltaV1 JSON Schema for installed imports."""
from __future__ import annotations

import json

from wiki_spike.resources import load_state_delta_schema_bytes

_raw: object = json.loads(load_state_delta_schema_bytes().decode("utf-8"))
if not isinstance(_raw, dict):
    raise TypeError("StateDelta schema must be a JSON object")
STATE_DELTA_SCHEMA: dict[str, object] = _raw
