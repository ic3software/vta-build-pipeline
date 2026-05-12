# Default `cross_community_relationships` policy — deny-all
# (spec §7.1).
#
# Storing a VRC issued by another community is opt-in by
# default. Operators who want to honour external relationship
# credentials upload a stricter policy. Phase 3+ surface — the
# stub ships now so `relationships.rego` doesn't have to
# special-case missing peer policies.
#
# Input shape (spec §7.3):
#   { vrc, viewer_member, vtc_state }

package vtc.cross_community_relationships

import rego.v1

default allow := false
