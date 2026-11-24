# openbao-operator: lets your own login (your userpass user) check how OpenBao is set
# up, and create a temporary root token when it also has the unseal key. It can't change
# anything by itself: policies, auth methods and the audit log need that root token.

# See the audit log configuration (listing audit devices needs sudo; enabling one is a
# different path, so this can't turn the audit log off or change it)
path "sys/audit" {
  capabilities = ["read", "sudo"]
}

# See which login methods are on (same: sudo to list, nothing to change)
path "sys/auth" {
  capabilities = ["read", "sudo"]
}

# Read policies and login settings, to compare them with the files in the repo
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/*" {
  capabilities = ["read"]
}
path "auth/userpass/users/*" {
  capabilities = ["read"]
}

# Check that no long-lived root tokens exist (token metadata only, never the tokens)
path "auth/token/accessors" {
  capabilities = ["list", "sudo"]
}
path "auth/token/lookup-accessor" {
  capabilities = ["update"]
}

# Create a temporary root token. This also needs the unseal key, so your login alone
# isn't enough: Initialize-OpenBao.ps1 uses it and revokes the token when it's done.
path "sys/generate-root-token/attempt" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}
path "sys/generate-root-token/update" {
  capabilities = ["create", "update", "sudo"]
}
