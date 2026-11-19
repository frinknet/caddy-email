# Test-only image: a Caddy binary whose "mta" app is a stub that does not
# implement shared.Enqueuer, so the sendmail template functions cannot wire
# themselves up. tests/e2e/container.sh runs it to check that startup fails with
# a clear error instead of panicking. The shipped image comes from the
# repository Dockerfile and never links this stub.
FROM caddy:2.11.9-builder-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -buildvcs=false -o /out/caddy ./tests/e2e/stubcaddy

# scratch has no shell, so COPY places the runtime directories Caddy needs.
RUN mkdir -p /out && : > /out/keep

FROM scratch

COPY --from=build /out/caddy /bin/caddy
COPY --from=build /out/keep   /etc/caddy/.keep
COPY --from=build /out/keep   /tmp/.keep

ENV PATH="/bin"
ENV HOME="/tmp"
ENV XDG_CONFIG_HOME="/etc/caddy"
ENV XDG_DATA_HOME="/tmp"

ENTRYPOINT ["/bin/caddy"]
CMD ["run"]
