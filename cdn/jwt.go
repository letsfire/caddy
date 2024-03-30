package cdn

import (
	"os"

	"github.com/golang-jwt/jwt"
)

// JwtClaims JWT请求体
type JwtClaims struct {
	jwt.StandardClaims
	Data map[string]interface{} `json:"data"`
}

// JwtParser JWT解析器
type JwtParser struct {
	keyFunc jwt.Keyfunc
}

func (p *JwtParser) Decode(s string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(s, &JwtClaims{}, p.keyFunc)
	return token.Claims.(*JwtClaims), err
}

func NewJwtParser(keyFile string) (*JwtParser, error) {
	var parser = new(JwtParser)
	if data, err := os.ReadFile(keyFile); err != nil {
		return parser, err
	} else {
		parser.keyFunc = func(t *jwt.Token) (interface{}, error) {
			return jwt.ParseRSAPublicKeyFromPEM(data)
		}
		return parser, nil
	}
}
