#!/bin/sh
# Unit checks in the builder image: format, vet, test.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

timeout 280 docker run --rm \
  -v caddy-sf-mod:/mod \
  -v "$ROOT":/src \
  -w /src \
  -e GOMODCACHE=/mod \
  -e GOCACHE=/mod/gocache \
  -e CGO_ENABLED=0 caddy:2.11.9-builder-alpine \
  sh -c 'gofmt -l . && go vet   ./... && go test -timeout=120s ./...'
