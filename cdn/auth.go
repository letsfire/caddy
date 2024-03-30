package cdn

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("cdn_auth", parseCdnAuthCaddyfile)
}

type Auth struct {
	parser *JwtParser
}

func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (p *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !strings.HasPrefix(r.URL.Path, "/caddy/cdn/auth") {
		return next.ServeHTTP(w, r)
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("x-access-token")
	}
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
	} else if _, err := p.parser.Decode(token); err != nil {
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
					p.parser, err = NewJwtParser(d.Val())
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
	if p.parser == nil {
		return d.Err("key file is empty")
	}
	return nil
}

func parseCdnAuthCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a Auth
	err := a.UnmarshalCaddyfile(h.Dispenser)
	return &a, err
}

var (
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
	_ caddyfile.Unmarshaler       = (*Auth)(nil)
)
