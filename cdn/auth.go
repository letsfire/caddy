package cdn

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type Auth struct {
	parser *JwtParser
}

func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

func (p *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
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

var (
	_ caddyhttp.Handler     = (*Auth)(nil)
	_ caddyfile.Unmarshaler = (*Auth)(nil)
)
