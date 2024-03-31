package caddy

import (
	v2 "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/letsfire/caddy/cdn"
)

func init() {
	v2.RegisterModule(&cdn.Auth{})

	httpcaddyfile.RegisterHandlerDirective("cdn_auth", parseCdnAuthCaddyfile)
}

// 解析CDN Auth配置
func parseCdnAuthCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a = new(cdn.Auth)
	return a, a.UnmarshalCaddyfile(h.Dispenser)
}
