package cdn

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
)

// JwtParser JWT解析器
type JwtParser struct {
	keyFunc jwt.Keyfunc
}

func (p *JwtParser) Decode(s string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(s, p.keyFunc)
	return token.Claims.(jwt.MapClaims), err
}

func NewJwtParser(keyFile string) (*JwtParser, error) {
	var parser = new(JwtParser)
	data, err := os.ReadFile(keyFile)
	if err == nil {
		parser.keyFunc = func(t *jwt.Token) (interface{}, error) {
			return jwt.ParseRSAPublicKeyFromPEM(data)
		}
	}
	return parser, err
}
