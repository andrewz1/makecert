package xdns

import (
	"net"
	"strings"
	"time"

	"github.com/andrewz1/xnet"
	"github.com/andrewz1/xtoml"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/log"
	"github.com/miekg/dns"

	"github.com/andrewz1/makecert/xt"
)

type Conf struct {
	Listen string `conf:"acme.listen"`
	SoaNS  string `conf:"acme.soa_ns,required"`

	ln  net.PacketConn
	srv *dns.Server
	st  *xt.Storage
}

var (
	opt = &Conf{
		Listen: "0.0.0.0:53",
		st:     xt.NewStorage(),
	}
)

func NewServer(conf string) (challenge.Provider, error) {
	var err error
	if err = xtoml.LoadConf(opt, conf); err != nil {
		return nil, err
	}
	if opt.ln, err = xnet.ListenPacket("udp", opt.Listen); err != nil {
		return nil, err
	}
	opt.srv = &dns.Server{PacketConn: opt.ln, Handler: opt}
	go opt.srv.ActivateAndServe()
	return opt, nil
}

func (c *Conf) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	rsp := &dns.Msg{}
	rsp.SetRcode(req, dns.RcodeSuccess)
	rsp.Authoritative = true
	defer func() {
		if err := w.WriteMsg(rsp); err != nil {
			log.Warnf("%v", err)
		}
	}()
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeTXT:
		rsp.Answer = append(rsp.Answer, c.buildTXT(q))
	case dns.TypeSOA:
		rsp.Answer = append(rsp.Answer, c.buildSOA(q))
	case dns.TypeNS:
		rsp.Answer = append(rsp.Answer, c.buildNS(q))
	}
}

func buildHdr(q dns.Question) dns.RR_Header {
	return dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  q.Qclass,
		Ttl:    1,
	}
}

func (c *Conf) buildSOA(q dns.Question) *dns.SOA {
	return &dns.SOA{
		Hdr:     buildHdr(q),
		Ns:      dns.CanonicalName(c.SoaNS),
		Mbox:    dns.CanonicalName("admin." + c.SoaNS),
		Serial:  100,
		Refresh: 30,
		Retry:   30,
		Expire:  3600,
		Minttl:  1,
	}
}

func (c *Conf) buildTXT(q dns.Question) *dns.TXT {
	t := &dns.TXT{
		Hdr: buildHdr(q),
	}
	v := c.st.Get(strings.ToLower(q.Name))
	if v == nil {
		return t
	}
	t.Txt = append(t.Txt, v.(string))
	return t
}

func (c *Conf) buildNS(q dns.Question) *dns.NS {
	return &dns.NS{
		Hdr: buildHdr(q),
		Ns:  dns.CanonicalName(c.SoaNS),
	}
}

func (c *Conf) Present(domain, _, keyAuth string) error {
	fqdn, value := dns01.GetRecord(strings.ToLower(domain), keyAuth)
	c.st.Put(fqdn, value)
	return nil
}

func (c *Conf) CleanUp(domain, _, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(strings.ToLower(domain), keyAuth)
	c.st.Del(fqdn)
	return nil
}

func (c *Conf) Sequential() time.Duration {
	return 5 * time.Second
}
