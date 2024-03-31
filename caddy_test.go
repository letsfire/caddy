package caddy

import (
	"context"
	"github.com/caddyserver/caddy/v2/caddytest"
	"net/http"
	"testing"
)

func TestCdnAuth(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		order cdn_auth after encode
	}

	localhost:9080 {
		cdn_auth {
			key_file 111
		}

		respond 404
	}
	`, "caddyfile")

	cx, _ := context.WithCancel(context.TODO())
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/caddy/cdn/auth", nil)
	req = req.WithContext(cx)
	tester.AssertResponseCode(req, http.StatusUnauthorized)
}
