# Default `personhood` policy — deny-all stub (spec §7.1 + §6.4).
#
# Phase 4 introduces the operator-facing
# `POST /v1/members/{did}/personhood/{assert,revoke}` endpoints
# and the real personhood-evidence evaluation. Until then the
# stub makes renewal's §6.3 step-3 personhood re-eval well-
# defined ("not asserted") — every renewed VMC carries
# `personhood: false`.
#
# Input shape (spec §7.3):
#   { applicant_did, vp_claims }

package vtc.personhood

import rego.v1

default allow := false

default asserted := false
