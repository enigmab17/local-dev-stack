# postgres-admin: everything the postgresql scripts need, and nothing else in OpenBao.
# Attached to your own login (your userpass user). Policies, auth methods, the audit
# log and unsealing stay with the root token.

# The database secrets engine: connection, roles, logins, rotation
path "database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# First-time setup enables the engine at database/
path "sys/mounts/database" {
  capabilities = ["create", "read", "update"]
}
path "sys/mounts" {
  capabilities = ["read"]
}

# Look up and revoke the short-lived logins the engine hands out
path "sys/leases/lookup" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
