package caddy

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/letsfire/caddy/cdn"
)

func init() {
	caddy.RegisterModule(&cdn.Auth{})
	caddy.RegisterModule(&cdn.Proxy{})
}
