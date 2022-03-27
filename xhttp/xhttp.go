package xhttp

import (
	"net"
	"net/http"

	"github.com/andrewz1/xnet"
	"github.com/andrewz1/xtoml"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/log"

	"github.com/andrewz1/makecert/xt"
)

type Conf struct {
	Listen string `conf:"acme.listen"`

	st  *xt.Storage
	ln  net.Listener
	srv *http.Server
}

var (
	opt = &Conf{
		Listen: "0.0.0.0:80",
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
	opt.srv = &http.Server{Handler: opt}
	go opt.srv.Serve(opt.ln)
	return opt, nil
}

func (c *Conf) Present(_, token, keyAuth string) error {
	c.st.Put(http01.ChallengePath(token), keyAuth)
	return nil
}

func (c *Conf) CleanUp(_, token, _ string) error {
	c.st.Del(http01.ChallengePath(token))
	return nil
}

func (c *Conf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer xt.CloseReq(r)
	v := c.st.Get(r.URL.Path)
	if v == nil {
		http.NotFound(w, r)
		return
	}
	vs := v.(string)
	w.Header().Set("content-type", "text/plain")
	if _, err := w.Write([]byte(vs)); err != nil {
		log.Warnf("%v", err)
	}
}
