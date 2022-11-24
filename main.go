package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	doh "github.com/likexian/doh-go"
	dohdns "github.com/likexian/doh-go/dns"

	"github.com/miekg/dns"
)

type dohHandler struct {
	appCtx  context.Context
	client  *doh.DoH
	timeout time.Duration

	hijackMap map[string][]string
}

func (d *dohHandler) parseQuery(ctx context.Context, m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			if arr, ok := d.hijackMap[q.Name]; ok {
				log.Printf("Direct response: %q", q.Name)
				for i := range arr {
					s := fmt.Sprintf("%s A %s", q.Name, arr[i])
					log.Println(s)
					rr, err := dns.NewRR(s)
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
				return
			}
			resp, err := d.client.Query(ctx, dohdns.Domain(q.Name), dohdns.TypeA)
			if err != nil {
				log.Printf("Query domain failed: %q", q.Name)
				return
			}
			for i := range resp.Answer {
				s := fmt.Sprintf("%s A %s", q.Name, resp.Answer[i].Data)
				log.Println(s)
				rr, err := dns.NewRR(s)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func (d *dohHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		ctx, cnl := context.WithTimeout(d.appCtx, d.timeout)
		defer cnl()
		d.parseQuery(ctx, m)
	}

	_ = w.WriteMsg(m)
}

func main() {
	var (
		timeout time.Duration
		port    int
	)

	flag.DurationVar(&timeout, "timeout", 10*time.Second, "query timeout for doh")
	flag.IntVar(&port, "port", 5300, "port to run dns on")

	flag.Parse()

	ctx, cnl := signal.NotifyContext(context.Background(), syscall.SIGILL)
	defer cnl()

	dohClient := &dohHandler{
		appCtx:  ctx,
		client:  doh.Use(doh.CloudflareProvider, doh.GoogleProvider, doh.Quad9Provider),
		timeout: 10 * time.Second,
		hijackMap: map[string][]string{
			"cloudflare-dns.com.": {"104.16.249.249", "104.16.248.249"},
			"dns.google.com.":     {"8.8.4.4", "8.8.8.8"},
			"dns9.quad9.net.":     {"9.9.9.9"},
		},
	}

	dns.Handle(".", dohClient)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
