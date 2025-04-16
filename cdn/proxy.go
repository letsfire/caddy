package cdn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/davidbyttow/govips/v2/vips"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

var sizeMap = map[string]int{"thumb": 320, "hd": 1600}

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
	var file = path.Base(r.URL.Path)
	var resize = filepath.Ext(file)
	if _, ok := sizeMap[resize]; !ok {
		errorResponse(fmt.Errorf("invalid %s", resize), w)
		return next.ServeHTTP(w, r)
	}
	var token = getParam(r, "x-access-token", "token")
	if claims, err := jwtParser.Decode(token); err != nil {
		errorResponse(err, w)
		return next.ServeHTTP(w, r)
	} else {
		// ID格式编码：a25041******
		var userId = strconv.Itoa(int(claims["user_id"].(float64)))
		if strings.HasPrefix(file[6:], userId) == false { // 非本人
			errorResponse(fmt.Errorf("user forbidden"), w)
			return next.ServeHTTP(w, r)
		}
	}
	var key = getParam(r, "x-encrypt-key", "key")
	if file[0:1] <= "k" { // 图片
		if res, err := getObject(r.URL.Path[1:], key); err != nil {
			errorResponse(err, w)
		} else {
			res, err = thumbnail(res, sizeMap[resize])
			if err != nil {
				errorResponse(err, w)
			} else if res, err = encrypt(key, res); err != nil {
				errorResponse(err, w)
			} else {
				_, _ = w.Write(res)
			}
		}
	} else { // 视频
		if cover, err := videoCover(r.URL.Path[1:], key); err != nil {
			errorResponse(err, w)
		} else if res, err := getObject(cover, key); err != nil {
			errorResponse(err, w)
		} else if res, err = thumbnail(res, sizeMap[resize]); err != nil {
			errorResponse(err, w)
		} else if res, err = encrypt(key, res); err != nil {
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

func decrypt(key string, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(MD5(key)))
	if err != nil {
		return nil, fmt.Errorf("%s - %s", err, key)
	} else if len(ciphertext) < 16 {
		return nil, errors.New("invalid ciphertext")
	}
	stream := cipher.NewCTR(block, ciphertext[:16])
	plaintext := make([]byte, len(ciphertext)-16)
	stream.XORKeyStream(plaintext, ciphertext[16:])
	return plaintext, nil
}

func encrypt(key string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(MD5(key)))
	if err != nil {
		return nil, fmt.Errorf("%s - %s", err, key)
	}
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("iv error: %v", err)
	}
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	return append(iv, ciphertext...), nil
}

func thumbnail(data []byte, size int) ([]byte, error) {
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
		_ = os.MkdirAll(path.Dir(tmpFile), os.ModePerm)
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
		cmd.Stdin = bytes.NewReader(res)
		if err := cmd.Run(); err != nil {
			return cover, err
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
		return decrypt(key, res)
	}
}
