# DIDComm Protocol Management — superseded

This page has been **superseded** by the unified runtime
service-management guide. The DIDComm-specific operator surface
(`pnm mediator …`, `pnm services {enable,disable} didcomm`) was
retired in P5 and replaced by the unified `pnm services …` tree
that covers REST and DIDComm symmetrically.

**See:** [`runtime-service-management.md`](runtime-service-management.md).

## Quick command rename map

| Retired | Current |
|---|---|
| `pnm services enable didcomm --mediator-did X` | `pnm services didcomm enable --mediator-did X` |
| `pnm services disable didcomm --drain-ttl 3600` | `pnm services didcomm disable --drain-ttl 86400` |
| `pnm mediator migrate --to X` | `pnm services didcomm update --to X` |
| `pnm mediator rollback --to X` | `pnm services didcomm rollback` (snapshot-driven) |
| `pnm mediator drain cancel --mediator-did X` | `pnm services didcomm drain cancel --mediator-did X` |
| `pnm mediator report` | `pnm services report` |

The old commands print "unknown subcommand" with no aliases — the
breaking-change posture was an explicit spec direction (no
production users at the time of P5).

The default `--drain-ttl` is now **24h** (was 1h), matching spec
§3.6.

The new doc covers the same material plus REST symmetry,
fail-forward rollback semantics, and the new `services list` /
`services didcomm drain list` queries.
