#!/bin/sh
# Downloads Forgejo's Swagger 2.0 spec at a release tag and vendors it as
# spec/forgejo-v<VERSION>.json. The source file is a Go template, not JSON:
# it only carries two placeholders ({{AppVer}} and {{AppSubUrl}}), so a sed
# is enough to turn it into a valid spec. AppSubUrl is emptied so basePath
# becomes "/api/v1" — the gateway prepends the instance URL itself.
set -eu

VERSION="${1:?usage: fetch-spec.sh <forgejo-version, e.g. 16.0.5>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/spec/forgejo-v$VERSION.json"

curl -fsSL "https://codeberg.org/forgejo/forgejo/raw/tag/v$VERSION/templates/swagger/v1_json.tmpl" |
  sed -e "s/{{AppVer | JSEscape}}/$VERSION/" -e 's/{{AppSubUrl | JSEscape}}//' |
  jq --indent 2 . >"$OUT"

echo "Vendored $OUT"
