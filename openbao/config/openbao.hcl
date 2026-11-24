ui            = true
disable_mlock = true   # needed on Docker Desktop

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # local only
}

api_addr = "http://localhost:8200"

# Audit log: every request and response, one JSON line each, to stdout, so
# 'docker logs openbao' shows it and Docker's log limits cap its size. Declared
# here because OpenBao no longer lets the API create audit devices (a security
# fix); it's loaded on startup and when the server receives SIGHUP.
audit "file" "to-stdout" {
  description = "Every request, to stdout (docker logs openbao)"
  options = {
    file_path = "stdout"
  }
}
