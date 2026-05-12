# Default `relationships` policy — store iff both parties are
# current members (spec §7.1).
#
# A VRC names two parties (issuer + subject). The default
# behaviour is to accept the publication only when both DIDs
# are current members of this community — preserves the "we
# don't publish relationship claims that span unknown parties"
# privacy floor. Operators relax by uploading their own
# policy.
#
# The handler enriches each party with an `is_current` flag
# (true iff the DID has an active ACL row and the Member row
# is not tombstoned). Default policy reads only that flag —
# the handler picks the canonical shape that future operator-
# authored policies will inherit.
#
# Input shape (spec §7.3, enriched):
#   { vrc, issuer_member: { did, is_current },
#          subject_member: { did, is_current },
#     action }

package vtc.relationships

import rego.v1

default allow := false

allow if {
	input.action == "publish"
	input.issuer_member.is_current
	input.subject_member.is_current
}
