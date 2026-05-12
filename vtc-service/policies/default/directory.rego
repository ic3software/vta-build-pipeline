# Default `directory` policy — members see DID + role only
# (spec §7.1 + §12.3).
#
# The directory endpoint lands in Phase 5 (community-facing
# member directory). The default-deny envelope here describes
# the privacy floor: any field beyond `did` + `role` is denied
# unless the operator uploads a wider-scope policy. Audit + the
# admin-facing `GET /v1/members` already bypass this — it's the
# *member-to-member* visibility surface this policy gates.
#
# Input shape (spec §7.3):
#   { viewer_did, viewer_role, target_member, fields_requested,
#     action }

package vtc.directory

import rego.v1

default allow := false

allowed_fields := {"did", "role"}

allow if {
	input.action == "show"
	every f in input.fields_requested {
		allowed_fields[f]
	}
}
