package cdn

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"net/http"
)

type Auth struct{}

func (*Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (p *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	token := getParam(r, "x-access-token", "token")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else if _, err := jwtParser.Decode(token); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	return next.ServeHTTP(w, r)
}

func (p *Auth) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "key_file":
				if d.NextArg() {
					jwtParser, err = NewJwtParser(d.Val())
					return err
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if jwtParser == nil {
		return d.Err("key file is empty")
	}
	return nil
}

var (
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
