# OAuth2 applications only exist under `/user/applications/oauth2`, scoped
# to the calling user — there is no admin or org route. The operator acts
# on another user's behalf with Forgejo's `Sudo` header, which patch 10
# removed as a security scheme (it was being sent on every call). Declaring
# it as an explicit optional header *parameter* on just these operations
# makes the generator expose it per call, set only when we mean it.
.paths |= with_entries(
  if (.key | startswith("/user/applications/oauth2")) then
    .value |= with_entries(
      if (.value | type) == "object" and (.value | has("operationId")) then
        .value.parameters = ((.value.parameters // []) + [{
          "name": "Sudo",
          "in": "header",
          "type": "string",
          "required": false,
          "description": "Act as this user (site administrators only)."
        }])
      else . end
    )
  else . end
)
