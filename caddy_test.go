package caddy

import (
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
			key_file G:/vvtime/api/config/files/rsa/public
		}
	}
	`, "caddyfile")

	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9080/caddy/cdn/auth?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3MTE4NzA5ODIsInVzZXJfaWQiOjE2LCJkZXZpY2VfaWQiOiJ0ZXN0IiwidHlwZSI6ImFjY2Vzc190b2tlbiJ9.aWFiss6AiF330kFYyU9HA-nKzfZmqkXvPcokmjC84OV2sF_NQhR489UPhvWCRh5xtxyU6OVq6j3HzK_Kn_R3_XkDf-McAt4_gVaaTxI4jd7Y1wd-a3-539Vl6dEMsk-j7dsje2Tr9_5m9-js8Ns-L6sdxBGkaSoh136e6I-UfPbCIdkw8pVoxSzKsGreAS2oQYyHsHcxnPrdyJ3QEB0ot4Emuj6IJLza97ByDsveR-9fDTvJm-CV4fxEC7tySm6JFazE0v3bmkuWlJ0G700-g2ye3BtUWlIXkcLjI4rBiENsyyzjey-yXzC0gtbkmlnJd9imGayj_nNoLS2fTvQRHw", nil)
	tester.AssertResponseCode(req, http.StatusOK)
}
