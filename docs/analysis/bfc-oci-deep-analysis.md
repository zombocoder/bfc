# Deep Analysis: bfc OCI module (ownership + round-trip)

**Coverage**: Degraded{missing: CodebaseMemory corroboration}
**Pillars**: graphify ✓ (21 facts, anchored) · codebase-memory ✓ indexed (1659 nodes / 2781 edges) but the `code-intel` adapter returned 0 facts for it — structure gathered by hand via MCP `query_graph`, per the documented fallback.

## Structure — WHO + HOW (codebase-memory, by hand)

- **Consumers of the OCI API**: `tests/unit/test_oci.c` only, plus internal self-calls inside `src/lib/bfc_oci.c`. No CLI, no other library callers.
  → **The public ownership contract can still be chosen freely; there are no downstream consumers to break.**
- `bfc_free_oci_layer` / `bfc_free_oci_manifest` are called both internally (`bfc_oci.c`) and from the test suite.

## Rationale — WHY (graphify)

- All OCI symbols land in **one community (3)** — a cohesive, well-bounded module; no god-node, no cross-cutting entanglement. The feature is structurally clean; the defects are local to its contract.

## Conclusion (Belnap synthesis)

| Claim | Verdict | Provenance | Anchor |
|---|---|---|---|
| `bfc_list_oci_layers` allocates ONE contiguous `calloc(n, sizeof(bfc_oci_layer_t))` array of **structs** | **True** | Both (graphify anchor + read source) | `src/lib/bfc_oci.c:470` |
| `bfc_free_oci_layers` iterates that memory as an array of **pointers** (`bfc_free_oci_layer(layers[i])`) | **True** | Both | `src/lib/bfc_oci.c:631` |
| ⇒ The two are **incompatible**: pairing them reinterprets `digest`/`media_type` pointer bytes as struct pointers and frees them | **True** | Synthesized | `:470` ↔ `:631` |
| `bfc_free_oci_manifest` ends in `free(manifest)` while `bfc_get_oci_manifest` fills a **caller-owned** struct (tests pass a stack local) | **True** | Both | `:557` ↔ `:392` |
| Writer stores layers at `blobs/sha256/%s`; extractor lists prefix `"layers/"` | **True** | Both | `:236` vs `:326` |
| ⇒ Extraction can never match a layer; returns `BFC_OK` with 0 files (silent) | **True** | Synthesized | `:326` |
| `blobs/sha256/%s` with a spec digest (`sha256:ab…`) yields `blobs/sha256/sha256:ab…` — algorithm twice | **True** | Read source | `:236` |
| OCI module is one cohesive community; boundary is sound | **True** | Graphify | `:1` |

No **Conflicted** claims — the pillars did not disagree anywhere.

## Decision: the ownership rule

**The caller owns the struct; the library owns the fields.**

- Getters (`bfc_get_oci_manifest`, `bfc_get_oci_config`) keep their `T*` out-param and fill a caller-provided struct — the natural C idiom and no public signature change.
- `bfc_free_oci_manifest` / `_config` / `_layer` release **fields only** and zero the struct; they no longer `free()` the struct itself.
- `bfc_list_oci_layers` keeps returning one contiguous array; `bfc_free_oci_layers` changes `bfc_oci_layer_t**` → `bfc_oci_layer_t*` and frees each element's fields, then the array once.
- `bfc_free_oci_index` owns its `manifests[i]` pointers, so it frees fields **and** each pointer.

Chosen over "getters allocate and return `**`" because it preserves the existing getter signatures and matches how the tests already declare structs (`bfc_oci_manifest_t m = {0};`).

## Gaps

- codebase-memory contributed no facts through the `code-intel` adapter despite a fresh index — adapter query path is worth a look (structure here was obtained via MCP directly).
- Windows/MSVC path is unanalyzed: the module uses `open_memstream`/`fmemopen`/2-arg `mkdir`/`<unistd.h>`/`<libgen.h>`, none available under MSVC.
