#!/bin/sh
# entrypoint.sh — caddy-email container startup
# Generates a minimal Caddyfile if one doesn't exist, then exec caddy.

set -e

CONFIG="${XDG_CONFIG_HOME:-/etc/caddy}/Caddyfile"

if [ ! -f "$CONFIG" ]; then
    cat > "$CONFIG" <<'EOF'
{
    admin off
    mta {
        spool_dir /var/lib/caddy/spool
    }
}

:80 {
    route /sendmail/* {
        sendmail
    }
}
EOF
    echo "entrypoint: generated default Caddyfile at $CONFIG"
fi

exec /bin/caddy run --config "$CONFIG" --adapter caddyfile "$@"
