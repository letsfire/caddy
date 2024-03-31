package cdn

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var parser *JwtParser

func init() {
	httpcaddyfile.RegisterHandlerDirective("cdn_auth", ParseCaddyfile)
}

type Auth struct{}

func (*Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (p *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !strings.HasPrefix(r.URL.Path, "/caddy/cdn/auth") {
		return next.ServeHTTP(w, r)
	}
	token := r.Header.Get("x-access-token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else if _, err := parser.Decode(token); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	return nil
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
					parser, err = NewJwtParser(d.Val())
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
	if parser == nil {
		return d.Err("key file is empty")
	}
	return nil
}

func ParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a = new(Auth)
	return a, a.UnmarshalCaddyfile(h.Dispenser)
}

var (
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
