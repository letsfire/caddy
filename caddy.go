package caddy

import (
	v2 "github.com/caddyserver/caddy/v2"
	"github.com/letsfire/caddy/cdn"
)

func init() {
	v2.RegisterModule(&cdn.Auth{})
}
