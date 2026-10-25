package aegis.authz

import rego.v1

# Aegis policy contract:
#   decision: "allow" | "suspend" | "deny"
#   reason:   human-readable explanation
#
# Anything not explicitly allowed is denied. Evaluation errors and timeouts are
# converted to "deny" by the gateway, so this file does not need a catch-all
# error rule.

default decision := "deny"
default reason := "implicitly denied by fail-closed default posture"

metadata_endpoints := {
	"169.254.169.254",
	"169.254.169.253",
	"169.254.170.2",
	"169.254.170.23",
	"metadata.google.internal",
	"metadata.goog",
	"100.100.100.200",
	"fd00:ec2::254",
}

mutating_sql_keywords := [
	"ALTER", "ATTACH", "CALL", "CREATE", "DELETE", "DETACH", "DROP", "EXEC",
	"GRANT", "INSERT", "MERGE", "PRAGMA", "REPLACE", "REVOKE", "TRUNCATE",
	"UPDATE", "VACUUM",
]

scopes := object.get(input, "delegated_scopes", [])

arg(name) := object.get(object.get(input, "args", {}), name, "")

# ---------------------------------------------------------------------------
# Unconditional deny: SSRF / cloud metadata access
# ---------------------------------------------------------------------------

decision := "deny" if {
	input.tool == "execute_code"
	is_metadata_target(arg("code"))
}

decision := "deny" if {
	input.tool == "http_request"
	is_metadata_target(arg("url"))
}

reason := "SSRF attempt to cloud metadata endpoint blocked" if {
	input.tool == "execute_code"
	is_metadata_target(arg("code"))
}

reason := "SSRF attempt to cloud metadata endpoint blocked" if {
	input.tool == "http_request"
	is_metadata_target(arg("url"))
}

# ---------------------------------------------------------------------------
# Human-in-the-loop: mutating SQL or production deployment
# ---------------------------------------------------------------------------

decision := "suspend" if {
	input.tool == "query_db"
	"query_db" in scopes
	is_mutating_sql(arg("query"))
}

decision := "suspend" if {
	input.tool == "deploy_service"
	"deploy_service" in scopes
	lower(arg("env")) == "prod"
}

reason := "mutating SQL or production action requires human sign-off" if {
	decision == "suspend"
}

# ---------------------------------------------------------------------------
# Deterministic allow: read-only bounded SQL within delegated scope
# ---------------------------------------------------------------------------

decision := "allow" if {
	input.tool == "query_db"
	"query_db" in scopes
	is_safe_read_sql(arg("query"))
}

# ---------------------------------------------------------------------------
# Deterministic allow: sandboxed code execution within delegated scope
# ---------------------------------------------------------------------------

decision := "allow" if {
	input.tool == "execute_code"
	"execute_code" in scopes
	not is_metadata_target(arg("code"))
}

# ---------------------------------------------------------------------------
# Deterministic allow: allow-listed HTTPS egress within delegated scope
# ---------------------------------------------------------------------------

decision := "allow" if {
	input.tool == "http_request"
	"http_request" in scopes
	startswith(arg("url"), "https://api.github.com/")
	not is_metadata_target(arg("url"))
}

reason := "permitted by deterministic policy" if {
	decision == "allow"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

is_metadata_target(s) if {
	is_string(s)
	some endpoint in metadata_endpoints
	contains(lower(s), endpoint)
}

# Block the whole IPv4 link-local range and IPv6 link-local addresses rather
# than only the well-known metadata IPs.
is_metadata_target(s) if {
	is_string(s)
	regex.match(`\b169\.254\.\d{1,3}\.\d{1,3}\b`, s)
}

is_metadata_target(s) if {
	is_string(s)
	contains(lower(s), "fe80::")
}

is_mutating_sql(q) if {
	is_string(q)
	normalized := normalize_sql(q)
	some kw in mutating_sql_keywords
	regex.match(sprintf(`(^|[^A-Z0-9_])%s([^A-Z0-9_]|$)`, [kw]), normalized)
}

# Safe reads must be a single SELECT/CTE statement with an explicit, bounded
# LIMIT. This is intentionally conservative: false negatives deny rather than
# allow an unbounded read.
is_safe_read_sql(q) if {
	is_string(q)
	normalized := normalize_sql(q)
	not contains(normalized, ";")
	not is_mutating_sql(q)
	regex.match(`^(SELECT|WITH)\b`, normalized)
	regex.match(`\bLIMIT\s+([1-9][0-9]{0,2}|1000)\s*$`, normalized)
}

normalize_sql(q) := upper(trim_space(regex.replace(
	regex.replace(regex.replace(q, `(?s)/\*.*?\*/`, " "), `--[^\n]*`, " "),
	`\s+`, " ",
))) if is_string(q)
