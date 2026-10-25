package aegis.authz

import rego.v1

default decision := "deny"
default reason := "implicitly denied by fail-closed default posture"

# 1. Unconditional Deny: Destructive shell patterns or cloud metadata SSRF
decision := "deny" if {
	input.tool == "execute_code"
	contains(lower(input.args.code), "169.254.169.254")
}

reason := "SSRF attempt to cloud metadata endpoint blocked" if {
	input.tool == "execute_code"
	contains(lower(input.args.code), "169.254.169.254")
}

# 2. Human-in-the-Loop (HITL) Suspension: Mutating queries or production deploys
decision := "suspend" if {
	input.tool == "query_db"
	is_mutating_sql(input.args.query)
	not is_Deny(input)
}

decision := "suspend" if {
	input.tool == "deploy_service"
	input.args.env == "prod"
}

reason := "mutating SQL or production action requires human sign-off" if {
	decision == "suspend"
}

# 3. Deterministic Allow: Read-only bounded SQL queries within delegated scope
decision := "allow" if {
	input.tool == "query_db"
	"query_db" in input.delegated_scopes
	not is_mutating_sql(input.args.query)
	contains(upper(input.args.query), "LIMIT ")
}

# 4. Deterministic Allow: Sandboxed code execution if scope permits
decision := "allow" if {
	input.tool == "execute_code"
	"execute_code" in input.delegated_scopes
	not contains(lower(input.args.code), "169.254.169.254")
}

# 5. Deterministic Allow: External API call with zero-trust secret injection
decision := "allow" if {
	input.tool == "http_request"
	"http_request" in input.delegated_scopes
	startswith(input.args.url, "https://api.github.com/")
}

reason := "permitted by deterministic policy" if {
	decision == "allow"
}

is_mutating_sql(q) if {
	u := upper(q)
	some kw in ["DROP ", "DELETE ", "UPDATE ", "INSERT ", "ALTER ", "TRUNCATE "]
	contains(u, kw)
}

is_Deny(x) if {
	false
}
