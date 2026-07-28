"""Explicit test-only bridge to the retired V1 MCP server.

This module is intentionally not imported by product composition, transports, or
the installed CLI.  It exists solely so compatibility tests can exercise a
frozen V1 fixture while product construction remains V2-only.
"""
from __future__ import annotations

from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.mcp import McpNonceGuard, McpServer
from wiki_spike.infrastructure.keystore import CreateOnlyKeyStore


def create_compat_mcp_v1(
    *,
    workspace_id: str,
    derived_keys: dict[str, bytes],
    database: LifecycleDatabase,
    cas: EncryptedContentStore,
    dek: bytes,
    platform_keystore: CreateOnlyKeyStore | None = None,
    recovery_keystore: CreateOnlyKeyStore | None = None,
    nonce_guard: McpNonceGuard | None = None,
) -> McpServer:
    """Construct V1 only for explicit compatibility tests.

    Callers must provide every legacy dependency, including direct key
    material.  No product object may call this factory.
    """
    return McpServer(
        workspace_id=workspace_id,
        derived_keys=derived_keys,
        db=database,
        cas=cas,
        dek=dek,
        platform_keystore=platform_keystore,
        recovery_keystore=recovery_keystore,
        nonce_guard=nonce_guard,
    )
