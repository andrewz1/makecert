package xacme

import (
	"crypto"
	"fmt"

	"github.com/andrewz1/xtoml"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/log"

	"github.com/andrewz1/makecert/xt"
)

type UCert struct {
	CrtType    string   `conf:"cert.type"`
	CrtKeyFile string   `conf:"cert.key,required"`
	CrtFile    string   `conf:"cert.cert,required"`
	CrtDom     []string `conf:"cert.domains,required"`
	MustStaple bool     `conf:"cert.must_staple"`

	key     crypto.PrivateKey
	keyType int
}

func newUCert(conf string) (*UCert, error) {
	u := &UCert{
		CrtType: "rsa2048",
	}
	if err := xtoml.LoadConf(u, conf); err != nil {
		return nil, err
	}
	if err := u.initKey(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UCert) initKey() error {
	if u.loadKey() {
		return nil
	}
	if err := u.parseType(); err != nil {
		return err
	}
	if err := u.genKey(); err != nil {
		return err
	}
	if err := u.saveKey(); err != nil {
		return err
	}
	return nil
}

func (u *UCert) loadKey() bool {
	var err error
	if u.key, u.keyType, err = xt.LoadKey(u.CrtKeyFile); err != nil {
		log.Warnf("load key: %v", err)
		return false
	}
	return true
}

func (u *UCert) parseType() error {
	if u.keyType = xt.KeyFromName(u.CrtType); u.keyType == xt.KeyInvalid {
		return fmt.Errorf("unsupported key type: %s", u.CrtType)
	}
	return nil
}

func (u *UCert) genKey() (err error) {
	u.key, err = xt.GenKey(u.keyType)
	return
}

func (u *UCert) saveKey() error {
	return xt.SaveKey(u.CrtKeyFile, u.key)
}

func (u *UCert) request() certificate.ObtainRequest {
	return certificate.ObtainRequest{
		Domains:    u.CrtDom,
		Bundle:     true,
		PrivateKey: u.key,
		MustStaple: u.MustStaple,
	}
}
