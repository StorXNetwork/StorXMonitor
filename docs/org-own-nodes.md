# Node group own-nodes

## Modes (unchanged)

| Mode | Behavior |
|------|----------|
| `default` | Public CyberLS network |
| `external_s3` | User S3 app via gateway |
| `own_nodes` | Org-connected nodes (check-in maps into `org_nodes`) |

## Minimum nodes (10)

When storage mode is `own_nodes`, backups require **at least 10** claimed org nodes (`MinOwnNodesRequired`).

| Action | Behavior if `nodeCount < 10` |
|--------|------------------------------|
| Job create (onboarding / add account) | Jobs **created inactive** (`active=false`); response includes `own_nodes` + `jobs_created_inactive: true` |
| Activate job / bulk activate | **Blocked** — `422` `ErrOwnNodesInsufficient` with message |
| Deactivate | Always allowed |
| Dashboard alerts | Extra field `own_nodes` for sidebar warning |
| Node setup / storage-destination | `ready`, `nodeCount`, `minNodes`, `message` |

Public / external S3 modes are not gated by node count.

## Onboarding UX

1. Select **My storage nodes**
2. **Create node group** (name)
3. **Show node connection commands** with `user-id` baked in
4. User runs commands on each machine; check-in auto-maps into `org_nodes`
5. Refresh the node list — sidebar warns until `nodeCount >= 10`
6. Create backup jobs (inactive until 10 nodes); activate when ready

Selecting **My storage nodes** also sets:

- `user_storage_destinations.mode = own_nodes`
- `users.default_placement = 250` (`OwnNodesPlacement`)
- `projects.default_placement = 250` and `projects.own_nodes_org_id` for active projects

New buckets/uploads then use claimed org nodes. Existing buckets created under public placement keep placement `0` until recreated.

## Upload requirement (why “requested 10, found 0”)

Own-nodes uploads need **≥ RS total** (local sim: **10**) claimed nodes that also qualify for the overlay **upload selection cache**:

- online within `overlay.node.online-window`
- `free_disk >= overlay.node.minimum-disk-space` (default **5GB** if unset)
- not disqualified / suspended / exiting

If claimed nodes advertise less free disk than the satellite minimum (e.g. CyberLS `STORAGE=500MB` while satellite still uses 5GB), selection returns **found 0** even though check-in and `org_nodes` look fine. Fix by raising node allocated disk **or** lowering `overlay.node.minimum-disk-space` on the satellite (and restarting).

## Operator flags (storagenode / docker)

```yaml
operator:
  email: you@example.com          # contact (stored in nodes.email)
  wallet: xdc…
  user-id: <console-user-uuid>    # CyberLS own-nodes bind
```

Storage-Node `.env`:

```text
EMAIL=you@example.com
WALLET=xdc…
USER_ID=<console-user-uuid>
```

Docker entrypoint maps `USER_ID` → `--operator.user-id`.

Check-in operator email encoding:

- With email + user-id: `ownnodes:<userUUID>|<you@example.com>`
  - Satellite maps with `ownnodes:<userUUID>`
  - Satellite stores `you@example.com` in `nodes.email`
- User-id only (no email): `ownnodes:<userUUID>` (legacy display)
- Legacy org form still parsed: `ownnodes:<userUUID>:<orgUUID>[|<email>]`

## APIs

- `GET/POST /api/v0/orgs`, `GET .../nodes`, `GET .../node-setup` (`ready` / `minNodes`)
- `GET/PUT /api/v0/storage-destination` — includes `own_nodes` capacity
- `GET /api/v0/google-backup/users-groups/dashboard-alerts` — includes `own_nodes`
- Job create / activate gated as above (see Minimum nodes)

Personal `/api/v0/user-nodes` claim APIs are removed. Ownership is **org_nodes** only (via check-in). Dedicated public-pool exclusion uses `org_nodes.AllNodeIDs()`.

## Tables

- `organizations`, `org_members`, `org_nodes`
- `projects.own_nodes_org_id` + `projects.default_placement` (set by storage-destination when mode is `own_nodes`)
- `user_storage_destinations`
