package cdn

import (
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"io"
	"net/http"
)

type Proxy struct{}

func (p *Proxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_proxy",
		New: func() caddy.Module { return new(Proxy) },
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	key := getParam(r, "x-encrypt-key", "key")
	if reader, err := ossBucket.GetObject(); err != nil {
		return err
	} else if bytes, err := io.ReadAll(reader); err != nil {
		return err
	} else {
	}
	return next.ServeHTTP(w, r)
}

func (p *Proxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var bucket = ""
	var endpoint = ""
	var accessKeyID = ""
	var accessKeySecret = ""
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "oss_bucket":
				if d.NextArg() {
					bucket = d.Val()
				}
			case "oss_endpoint":
				if d.NextArg() {
					endpoint = d.Val()
				}
			case "oss_access_key_id":
				if d.NextArg() {
					accessKeyID = d.Val()
				}
			case "oss_access_key_secret":
				if d.NextArg() {
					accessKeySecret = d.Val()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	ossClient, err := oss.New(endpoint, accessKeyID, accessKeySecret)
	if err == nil {
		ossBucket, err = ossClient.Bucket(bucket)
	}
	return err
}

var (
	_ caddyhttp.MiddlewareHandler = (*Proxy)(nil)
	_ caddyfile.Unmarshaler       = (*Proxy)(nil)
)
