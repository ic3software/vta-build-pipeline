# Default `personhood` policy — minimal-allow (Phase 4 M4.2).
#
# This is the **default** personhood evaluator. Operators
# replace it via `POST /v1/policies` + `POST /v1/policies/{id}/activate`
# to express richer evidence requirements (proof-of-personhood,
# multi-witness, biometric attestation, etc).
#
# ## Minimal-allow semantics
#
# The policy returns `allow == true` when the applicant's VP
# carries at least one `WitnessCredential` from a non-empty
# issuer. This is intentionally permissive — operators with
# stricter requirements upload a custom rego. The default lets
# the workspace's integration tests exercise the assert flow
# without operator setup.
#
# ## Input shape
#
# Driven from two call sites:
#
# 1. **Assert endpoint** (M4.3):
#    {
#      "applicant_did": "<member-did>",
#      "vp_claims": {
#        "holder": "<member-did>",
#        "credentials": [ { "type": [...], "issuer": "<did>", ... }, ... ]
#      }
#    }
#
# 2. **Renewal-time re-evaluation** (M4.2.2):
#    {
#      "applicant_did": "<did>",
#      "current_personhood": <bool>,
#      "asserted_at_seconds_ago": <int | null>,
#      "vp_claims": { "holder": "<did>", "credentials": [] }
#    }
#
#    The default re-evaluator preserves an existing
#    `current_personhood == true` — assertions don't lapse on
#    renewal under the default policy. Operators wanting
#    time-based expiry override `asserted_within_max_age`.

package vtc.personhood

import rego.v1

# Default-deny when no rule below fires.
default allow := false

# `asserted` mirrors `allow` for legacy call sites that read
# the old name.
asserted if allow

# ── Assert path (default minimal-allow) ────────────────────

# Allow when the applicant presents at least one
# `WitnessCredential` from a non-empty issuer.
allow if {
	some i
	cred := input.vp_claims.credentials[i]
	"WitnessCredential" in cred.type
	cred.issuer != ""
}

# ── Renewal-time re-eval (preserve existing assertion) ─────

# When renewal sees a member whose flag is already `true`,
# preserve it. Operators wanting time-based expiry override
# this rule with their own age check.
allow if {
	input.current_personhood == true
}
