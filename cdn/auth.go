package cdn

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

var parser *JwtParser

func init() {
	httpcaddyfile.RegisterHandlerDirective("cdn_auth", ParseCaddyfile)
}

func getParam(r *http.Request, headerKey string, queryKey string) string {
	if headerVal := r.Header.Get(headerKey); headerVal != "" {
		return headerVal
	}
	return r.URL.Query().Get(queryKey)
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
	resId := getParam(r, "x-resource-id", "id")
	token := getParam(r, "x-access-token", "token")
	if token == "" || len(resId) < 9 {
		w.WriteHeader(http.StatusUnauthorized)
	} else if data, err := parser.Decode(token); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		if strings.HasPrefix(resId[7:], strconv.Itoa(data["user_id"].(int))+"u") {

		}
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
