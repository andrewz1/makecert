package xalpn

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/andrewz1/xnet"
	"github.com/andrewz1/xtoml"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"

	"github.com/andrewz1/makecert/xt"
)

type Conf struct {
	Listen string `conf:"acme.listen"`

	st  *xt.Storage
	ln  net.Listener
	tln net.Listener
	cfg *tls.Config
	srv *http.Server
}

var (
	opt = &Conf{
		Listen: "0.0.0.0:443",
		st:     xt.NewStorage(),
	}
)

func NewServer(conf string) (challenge.Provider, error) {
	var err error
	if err = xtoml.LoadConf(opt, conf); err != nil {
		return nil, err
	}
	if opt.ln, err = xnet.Listen("tcp", opt.Listen); err != nil {
		return nil, err
	}
	opt.cfg = &tls.Config{
		GetCertificate: opt.getCert,
		NextProtos:     []string{tlsalpn01.ACMETLS1Protocol},
	}
	opt.tln = tls.NewListener(opt.ln, opt.cfg)
	opt.srv = &http.Server{Handler: opt}
	go opt.srv.Serve(opt.tln)
	return opt, nil
}

func (c *Conf) getCert(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	v := c.st.Get(h.ServerName)
	if v == nil {
		return nil, fmt.Errorf("invalid domain: %s", h.ServerName)
	}
	return v.(*tls.Certificate), nil
}

func (c *Conf) Present(domain, _, keyAuth string) error {
	crt, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}
	c.st.Put(domain, crt)
	return nil
}

func (c *Conf) CleanUp(domain, _, _ string) error {
	c.st.Del(domain)
	return nil
}

func (c *Conf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer xt.CloseReq(r)
	http.NotFound(w, r)
}
