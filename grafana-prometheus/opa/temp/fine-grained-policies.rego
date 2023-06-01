package authz.fine.policy

import data.Roles as roles
import data.Statements as policies
import future.keywords

# METADATA
# entrypoint: true
allow if {
	policy = policies[_]
	regex.match(policy.Resource, input.resource)
	policy.Method == input.method
	some index, role in input.roles
	some perm in findpermissionByRole(role)
	perm == policy.Permission
}

findpermissionByRole(r) = permission if {
	permission := roles[r]
}

# METADATA
# entrypoint: true
batch_allow = [url |
	some i
	url := input.resources[i]
	method := input.methods[i]
	allow with input as {
		"method": method,
		"resource": url,
		"roles": input.roles,
	}
]

