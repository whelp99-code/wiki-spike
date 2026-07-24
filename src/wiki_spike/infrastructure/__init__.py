"""Infrastructure layer for the Encrypted Single-Memory Lifecycle (Gate 2).

Architecture-boundary contract (see ``architecture-boundaries.json``): this
package MAY import ``wiki_spike.memory_core`` (ports/contracts) and the
Python standard library / third-party crypto libraries, but MUST NEVER
import ``wiki_spike.memory_runtime``, ``wiki_spike.applications``,
``wiki_spike.connectors``, ``wiki_spike.ui``, or any legacy storage module
(``cas``, ``controlplane``, ``generation``, ``gitrepo``, ``publish``,
``signing``, ``workspace``).
"""
from __future__ import annotations
