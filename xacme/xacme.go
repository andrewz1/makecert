package xacme

import (
	"crypto"
	"fmt"
	"io/ioutil"

	"github.com/andrewz1/xtoml"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"

	"github.com/andrewz1/makecert/xalpn"
	"github.com/andrewz1/makecert/xdns"
	"github.com/andrewz1/makecert/xhttp"
	"github.com/andrewz1/makecert/xt"
)

const (
	acmeKeyType = certcrypto.EC384
)

type Conf struct {
	AcmeStaging bool   `conf:"acme.staging"` // acme staging env
	AcmeKey     string `conf:"acme.key"`     // acme key file
	AcmeEmail   string `conf:"acme.email"`   // acme email
	AcmeType    string `conf:"acme.type"`    // acme challenge type

	key   crypto.PrivateKey
	keyT  certcrypto.KeyType
	u     *acmeUser
	p     challenge.Provider
	pType challenge.Type
	res   *certificate.Resource
	uc    *UCert
}

var (
	opt = &Conf{}
)

func Init(conf string) (err error) {
	if err = xtoml.LoadConf(opt, conf); err != nil {
		return
	}
	if opt.uc, err = newUCert(conf); err != nil {
		return
	}
	if err = opt.setupProvider(conf); err != nil {
		return
	}
	if err = opt.initKey(); err != nil {
		return
	}
	if opt.u, err = opt.makeUser(); err != nil {
		return
	}
	return nil
}

func (c *Conf) setupProvider(conf string) (err error) {
	switch c.AcmeType {
	case "", string(challenge.TLSALPN01):
		c.pType = challenge.TLSALPN01
		c.p, err = xalpn.NewServer(conf)
	case string(challenge.HTTP01):
		c.pType = challenge.HTTP01
		c.p, err = xhttp.NewServer(conf)
	case string(challenge.DNS01):
		c.pType = challenge.DNS01
		c.p, err = xdns.NewServer(conf)
	default:
		err = fmt.Errorf("unsupported acme provider: %s", c.AcmeType)
	}
	return err
}

func (c *Conf) loadKey() bool {
	if len(c.AcmeKey) == 0 {
		log.Warnf("no acme key set, generate new one")
		return false
	}
	var err error
	if c.key, c.keyT, err = xt.LoadKeyCr(c.AcmeKey); err != nil {
		log.Warnf("load acme key: %v", err)
		return false
	}
	return true
}

func (c *Conf) genKey() error {
	key, err := xt.GenKeyCr(acmeKeyType)
	if err != nil {
		return err
	}
	c.key = key
	c.saveKey()
	return nil
}

func (c *Conf) saveKey() {
	if len(c.AcmeKey) == 0 {
		return
	}
	if err := xt.SaveKey(c.AcmeKey, c.key); err != nil {
		log.Warnf("save acme key: %v", err)
	}
}

func (c *Conf) initKey() error {
	if !c.loadKey() {
		if err := c.genKey(); err != nil {
			return err
		}
	}
	c.keyT = xt.KeyTypeCr(c.key)
	if c.keyT == xt.KeyUnknown {
		return fmt.Errorf("unknown key type")
	}
	return nil
}

func (c *Conf) makeUser() (*acmeUser, error) {
	u := &acmeUser{
		email: c.AcmeEmail,
		key:   c.key,
	}
	cfg := lego.NewConfig(u)
	cfg.Certificate.KeyType = c.keyT
	if c.AcmeStaging {
		cfg.CADirURL = lego.LEDirectoryStaging
	}
	var err error
	if err = u.newClient(cfg); err != nil {
		return nil, err
	}
	if err = u.updateReg(); err != nil {
		return nil, err
	}
	switch c.pType {
	case challenge.TLSALPN01:
		err = u.cl.Challenge.SetTLSALPN01Provider(c.p)
	case challenge.HTTP01:
		err = u.cl.Challenge.SetHTTP01Provider(c.p)
	case challenge.DNS01:
		err = u.cl.Challenge.SetDNS01Provider(c.p)
	default:
		err = fmt.Errorf("unknown acme provider")
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func Obtain() error {
	req := opt.uc.request()
	res, err := opt.u.cl.Certificate.Obtain(req)
	if err != nil {
		return err
	}
	opt.res = res
	return nil
}

func Resource() *certificate.Resource {
	return opt.res
}

func Save() error {
	return ioutil.WriteFile(opt.uc.CrtFile, opt.res.Certificate, 0644)
}
