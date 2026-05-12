# Default `role_definitions` policy — spec §5.3 standard-role
# permission matrix. Custom roles (`Role::Custom(String)`)
# receive *no* implicit grants from this default; operators
# must upload an extended policy or rely on the explicit
# default-deny behaviour spec §5.3 calls out.
#
# Wire-form action names align with the spec table:
#   edit_community_profile      — Admin only
#   author_policies             — Admin only
#   approve_join / reject_join  — Admin, Moderator
#   issue_community_credential  — Admin, Issuer
#   issue_vmc                   — Admin only (and only via the
#                                  join-approve handler, not as a
#                                  standalone action — policy
#                                  permits it, the route layer
#                                  scopes the actual call site)
#   promote_to_admin            — Admin only
#   remove_member               — Admin, Moderator
#   self_remove                 — everyone
#   renew_vmc                   — everyone
#   publish_vrc                 — everyone
#   rotate_did                  — everyone
#
# Input shape (spec §7.3):
#   { role, action, resource? }

package vtc.role_definitions

import rego.v1

default allow := false

admin_actions := {
	"edit_community_profile",
	"author_policies",
	"approve_join", "reject_join",
	"issue_community_credential", "issue_vmc",
	"promote_to_admin",
	"remove_member",
	"self_remove",
	"renew_vmc",
	"publish_vrc",
	"rotate_did",
}

moderator_actions := {
	"approve_join", "reject_join",
	"remove_member",
	"self_remove",
	"renew_vmc",
	"publish_vrc",
	"rotate_did",
}

issuer_actions := {
	"issue_community_credential",
	"self_remove",
	"renew_vmc",
	"publish_vrc",
	"rotate_did",
}

member_actions := {
	"self_remove",
	"renew_vmc",
	"publish_vrc",
	"rotate_did",
}

allow if {
	input.role == "admin"
	admin_actions[input.action]
}

allow if {
	input.role == "moderator"
	moderator_actions[input.action]
}

allow if {
	input.role == "issuer"
	issuer_actions[input.action]
}

allow if {
	input.role == "member"
	member_actions[input.action]
}
