"""P4-13 body-free online operational telemetry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_int, content_id, verify_content_id, ensure_no_secret_keys, nonempty, safe_code, string_tuple

ONLINE_METRIC_VERSION = "phase4-online-metric-v1"


@dataclass(frozen=True)
class OnlineMetric:
    online_metric_version: str
    metric_id: str
    workspace_ref: str
    operation_ref: str
    metric_name: str
    value: str
    unit: str
    labels: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, *, workspace_ref: str, operation_ref: str, metric_name: str, value: str, unit: str, labels: Mapping[str, str] | None = None) -> "OnlineMetric":
        label_values = tuple(sorted((safe_code(key, "label_key"), safe_code(item, "label_value")) for key, item in (labels or {}).items()))
        payload = {
            "online_metric_version": ONLINE_METRIC_VERSION,
            "workspace_ref": workspace_ref,
            "operation_ref": operation_ref,
            "metric_name": metric_name,
            "value": value,
            "unit": unit,
            "labels": [{"key": key, "value": item} for key, item in label_values],
        }
        return cls(metric_id=content_id("wiki.runtime.online-metric.v1", payload), labels=label_values, **{k: v for k, v in payload.items() if k != "labels"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.online_metric_version != ONLINE_METRIC_VERSION:
            raise InvalidContractValue("unsupported online metric version")
        nonempty(self.workspace_ref, "workspace_ref")
        nonempty(self.operation_ref, "operation_ref")
        safe_code(self.metric_name, "metric_name")
        canonical_int(self.value, "value", maximum=10**18)
        safe_code(self.unit, "unit")
        forbidden = {"quality", "correct", "reward", "engagement"}
        if self.metric_name in forbidden:
            raise InvalidContractValue("online operations metrics must not claim answer correctness")
        verify_content_id(self.metric_id, "wiki.runtime.online-metric.v1", self.to_mapping(), "metric_id", "online metric_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "online_metric_version": self.online_metric_version,
            "metric_id": self.metric_id,
            "workspace_ref": self.workspace_ref,
            "operation_ref": self.operation_ref,
            "metric_name": self.metric_name,
            "value": self.value,
            "unit": self.unit,
            "labels": [{"key": key, "value": value} for key, value in self.labels],
        }


class TelemetrySink:
    def __init__(self) -> None:
        self.metrics: list[OnlineMetric] = []

    def emit(self, metric: OnlineMetric) -> None:
        ensure_no_secret_keys(metric.to_mapping(), label="telemetry")
        self.metrics.append(metric)


__all__ = ["ONLINE_METRIC_VERSION", "OnlineMetric", "TelemetrySink"]
