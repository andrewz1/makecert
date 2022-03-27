package xacme

import (
	"crypto"
	"strings"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
)

const (
	mailPfx = "mailto:"
)

type acmeUser struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
	cl    *lego.Client
}

var (
	opts    = registration.RegisterOptions{TermsOfServiceAgreed: true}
	mailLen = len(mailPfx)
)

func (u *acmeUser) GetEmail() string {
	return u.email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.reg
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *acmeUser) newClient(cfg *lego.Config) error {
	cl, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}
	u.cl = cl
	return nil
}

func (u *acmeUser) updateReg() error {
	reg, err := u.cl.Registration.ResolveAccountByKey()
	if err != nil {
		return u.registerUser()
	}
	var email string
	for _, v := range reg.Body.Contact {
		if strings.HasPrefix(v, mailPfx) {
			email = v[mailLen:]
			log.Infof("resolved email: %s", email)
			break
		}
	}
	u.reg = reg
	if len(email) > 0 {
		u.email = email
	}
	return nil
}

func (u *acmeUser) registerUser() error {
	reg, err := u.cl.Registration.Register(opts)
	if err != nil {
		return err
	}
	u.reg = reg
	return nil
}
