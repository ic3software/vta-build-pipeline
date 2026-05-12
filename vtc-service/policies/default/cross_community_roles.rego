# Default `cross_community_roles` policy — deny-all
# (spec §7.1 + §8.4).
#
# Honouring a foreign VEC's role grant is a session-mint
# hardening hazard (spec §8.4): a malicious peer community
# could mint arbitrary VECs and have them confer admin in your
# community. Default-deny forces the operator to make an
# explicit allowlist before any cross-community grant takes
# effect.
#
# Input shape (spec §7.3):
#   { foreign_vec, target_role, vtc_state }

package vtc.cross_community_roles

import rego.v1

default allow := false
