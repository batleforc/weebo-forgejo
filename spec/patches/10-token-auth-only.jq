# openapi-generator's rust target folds every `apiKey` security scheme into
# the single `Configuration.api_key`, so with Forgejo's spec the admin token
# would be sent as `Authorization`, `Sudo`, `?sudo=` *and* `X-FORGEJO-OTP`
# on every call — impersonating a user literally named "token <secret>".
# Keep token auth only; Sudo is set per call by the gateway as a plain
# header (see crates/adapters-outbound/src/forgejo_http/mod.rs).
.securityDefinitions |= { AuthorizationHeaderToken: .AuthorizationHeaderToken }
| .security = [ { AuthorizationHeaderToken: [] } ]
| (.paths[][] | objects | select(has("security"))) |= del(.security)
