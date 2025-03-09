package cdn

import (
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"net/http"
	"net/url"
)

var jwtParser *JwtParser
var ossBucket *oss.Bucket
var encryptKey string

// getParam 从header或query获取参数值
func getParam(r *http.Request, headerKey string, queryKey string) string {
	if headerVal := r.Header.Get(headerKey); headerVal != "" {
		return headerVal
	}
	queryVal, _ := url.QueryUnescape(r.URL.Query().Get(queryKey))
	return queryVal
}

// errorResponse 异常响应
func errorResponse(e error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(e.Error()))
}

func init() {
	httpcaddyfile.RegisterHandlerDirective("cdn_auth", ParseCdnAuthFile)
	httpcaddyfile.RegisterHandlerDirective("cdn_proxy", ParseCdnProxyFile)
}

func ParseCdnAuthFile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var a = new(Auth)
	return a, a.UnmarshalCaddyfile(h.Dispenser)
}

func ParseCdnProxyFile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p = new(Proxy)
	return p, p.UnmarshalCaddyfile(h.Dispenser)
}
