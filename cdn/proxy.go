package cdn

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/davidbyttow/govips/v2/vips"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func init() {
	vips.Startup(nil)
}

type Proxy struct{}

func (p *Proxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cdn_proxy",
		New: func() caddy.Module { return new(Proxy) },
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	token := getParam(r, "x-access-token", "token")
	claims, err := jwtParser.Decode(token)
	if err != nil {
		errorResponse(err, w)
		return next.ServeHTTP(w, r)
	}
	var user = int(claims["user_id"].(float64))
	var key = fmt.Sprintf(encryptKey, user)
	process := r.URL.Query().Get("x-oss-process")
	size, err := strconv.Atoi(strings.TrimLeft(process, "image/resize,l_"))
	if err != nil {
		errorResponse(err, w)
	} else if strings.HasPrefix(r.URL.Path, "/proxy/vod") {
		if cover, err := videoCover(r.URL.Path[11:], key); err != nil {
			errorResponse(err, w)
		} else if res, err := getObject(cover, ""); err != nil {
			errorResponse(err, w)
		} else {
			_, _ = w.Write(res)
		}
	} else {
		if res, err := getObject(r.URL.Path[11:], key); err != nil {
			errorResponse(err, w)
		} else if res, err = thumbnail(res, size); err != nil {
			errorResponse(err, w)
		} else {
			_, _ = w.Write(res)
		}
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
			case "encrypt_key":
				if d.NextArg() {
					encryptKey = d.Val()
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

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%s - %s", err, key)
	}
	blockSize := block.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for bs, be := 0, blockSize; bs < len(ciphertext); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
	}
	length := len(plaintext)
	padding := int(plaintext[length-1])
	return plaintext[:(length - padding)], nil
}

func thumbnail(data []byte, size int) ([]byte, error) {
	size = int(math.Max(float64(size), 240))
	img, err := vips.NewImageFromBuffer(data)
	if err == nil {
		err = img.ThumbnailWithSize(size, size, vips.InterestingNone, vips.SizeDown)
	}
	if err != nil {
		return nil, err
	}
	res, _, err := img.ExportNative()
	return res, err
}

func videoCover(object, key string) (string, error) {
	var cover = fmt.Sprintf("cover/%s.jpg", object)
	if exist, err := ossBucket.IsObjectExist(cover); exist && err == nil {
		return cover, nil
	}
	if res, err := getObject(object, key); err != nil {
		return cover, err
	} else {
		var tmpFile = fmt.Sprintf("/%s", object)
		err = os.WriteFile(tmpFile, res, os.ModePerm)
		if err != nil {
			return cover, fmt.Errorf("%s - %s", err, tmpFile)
		}
		defer func(name string) {
			_ = os.Remove(name)
		}(tmpFile) // 清除临时文件
		var out = bytes.NewBuffer(nil)
		cmd := exec.Command(
			"ffmpeg", "-i", tmpFile, "-ss", "00:00:00",
			"-vframes", "1", "-f", "image2pipe", "pipe:1",
		)
		cmd.Stdout = out
		cmd.Stderr = out
		cmd.Stdin = bytes.NewReader(res)
		if err := cmd.Run(); err != nil {
			return cover, fmt.Errorf("%s - %s", err, out.Bytes())
		} else if out.Len() == 0 {
			return cover, fmt.Errorf("ffmpeg output empty")
		} else {
			return cover, ossBucket.PutObject(cover, out)
		}
	}
}

func getObject(object, key string) ([]byte, error) {
	object, _ = url.QueryUnescape(object)
	if reader, err := ossBucket.GetObject(object); err != nil {
		return nil, fmt.Errorf("%s - %s", err.Error(), object)
	} else if res, err := io.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("%s - %s", err.Error(), object)
	} else {
		if key == "" {
			return res, nil
		}
		return decrypt([]byte(key), res)
	}
}
