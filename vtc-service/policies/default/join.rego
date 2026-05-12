# Default `join` policy — `policies.open` template (spec §7.1).
#
# Accepts every well-formed join request. The submit handler
# already verifies the holder-binding signature on the VP
# (Phase 1 M1.8.2); this policy decides whether to surface the
# request as `Pending` for admin review or reject it outright.
# Operators replace this with a stricter policy by uploading
# their own and activating it.
#
# Input shape (spec §7.3):
#   { applicant_did, vp_claims, action, now }

package vtc.join

import rego.v1

default allow := false

allow if input.action == "join"
