# Default `removal` policy — admin may remove any non-admin
# (spec §7.1 + §10.2). The route layer enforces:
#
# 1. `AdminAuth` on the admin-remove endpoint — so the caller is
#    already known to be an admin when this policy runs.
# 2. The no-last-admin invariant — the route refuses to leave
#    zero admins regardless of policy output.
# 3. Self-remove is its own unconditional endpoint
#    (`DELETE /v1/members/me`) and bypasses this policy entirely.
#
# This policy therefore only gates the "may this admin remove
# this target" question. Default: allow unless the target is
# also an admin (admins can only be removed by promotion + the
# step-up UV path, never via a casual admin-remove).
#
# Input shape (spec §7.3):
#   { actor_did, target_did, target_role, reason, action, now }

package vtc.removal

import rego.v1

default allow := false

allow if {
	input.action == "remove"
	input.target_role != "admin"
}

# Phase 1 plan §D6: `Disposition::PolicyDefault` resolves to
# whatever this policy emits. The default mirrors Phase 1's
# hardcoded `Tombstone` so existing operator state survives the
# Phase 1 → Phase 2 transition unchanged.
default min_disposition := "tombstone"

