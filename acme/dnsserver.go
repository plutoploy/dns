package acme

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func parseIP4(s string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// ---------------------------------------------------------------------------
// TXTStore – in-memory store of the ACME challenge TXT values, keyed by the
// challenge FQDN that the CA will query.
// ---------------------------------------------------------------------------

// TXTStore holds the current DNS-01 TXT values that the authoritative DNS
// server answers with. It is populated automatically by the DNS-01 provider
// during certificate issuance / renewal.
type TXTStore struct {
	mu     sync.RWMutex
	values map[string][]string // fqdn (lower, trailing dot) -> TXT values
}

// NewTXTStore creates an empty TXT store.
func NewTXTStore() *TXTStore {
	return &TXTStore{values: make(map[string][]string)}
}

func canonical(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// Set replaces the TXT values for an FQDN.
func (s *TXTStore) Set(fqdn string, values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[canonical(fqdn)] = values
}

// Add appends a TXT value for an FQDN (ACME may request multiple).
func (s *TXTStore) Add(fqdn, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := canonical(fqdn)
	s.values[k] = append(s.values[k], value)
}

// Remove deletes all TXT values for an FQDN.
func (s *TXTStore) Remove(fqdn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, canonical(fqdn))
}

// Get returns the TXT values for an FQDN.
func (s *TXTStore) Get(fqdn string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[canonical(fqdn)]
	return v, ok
}

// ---------------------------------------------------------------------------
// DNSServer – authoritative DNS server for the delegation zone.
//
// Domains delegate their _acme-challenge record to this server with a static
// CNAME once:
//
//	_acme-challenge.example.com.  CNAME  example.com.<delegation-zone>.
//
// This server then answers the TXT query for that target with the current
// ACME challenge value, so issuance is fully automated with only a CNAME.
// ---------------------------------------------------------------------------

// DNSServerConfig configures the authoritative DNS server.
type DNSServerConfig struct {
	// Zone is the delegation zone this server is authoritative for, e.g.
	// "auth.example.com". CNAME targets live under this zone.
	Zone string

	// Addr is the UDP/TCP listen address, e.g. ":53".
	Addr string

	// NSName is the hostname of this nameserver (for SOA/NS records), e.g.
	// "ns1.auth.example.com". Defaults to "ns1.<Zone>".
	NSName string

	// PublicIP, when set, is served as an A record for the NS name and zone
	// apex so the delegation resolves. Optional.
	PublicIP string
}

// DNSServer is a minimal authoritative server that answers TXT queries for
// ACME challenge records from a TXTStore.
type DNSServer struct {
	cfg   DNSServerConfig
	store *TXTStore
	zone  string // canonical zone (lower, trailing dot)
	ns    string // canonical NS name
	udp   *dns.Server
	tcp   *dns.Server
}

// NewDNSServer builds a DNS server bound to the given TXT store.
func NewDNSServer(cfg DNSServerConfig, store *TXTStore) *DNSServer {
	if cfg.Addr == "" {
		cfg.Addr = ":53"
	}
	if cfg.NSName == "" && cfg.Zone != "" {
		cfg.NSName = "ns1." + cfg.Zone
	}
	return &DNSServer{
		cfg:   cfg,
		store: store,
		zone:  canonical(cfg.Zone),
		ns:    canonical(cfg.NSName),
	}
}

// CNAMETarget returns the CNAME target the user must configure once for a
// domain, i.e. the value of _acme-challenge.<domain>.
//
//	_acme-challenge.<domain>.  CNAME  <target>
func (d *DNSServer) CNAMETarget(domain string) string {
	label := strings.TrimSuffix(strings.ToLower(domain), ".")
	label = strings.ReplaceAll(label, ".", "-")
	return fmt.Sprintf("%s.%s", label, strings.TrimSuffix(d.zone, "."))
}

// ChallengeFQDN returns the fully-qualified name (with trailing dot) that the
// CA will end up querying after following the CNAME.
func (d *DNSServer) ChallengeFQDN(domain string) string {
	return canonical(d.CNAMETarget(domain))
}

// ServeDNS handles incoming DNS queries.
func (d *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		name := canonical(q.Name)
		switch q.Qtype {
		case dns.TypeTXT:
			if vals, ok := d.store.Get(name); ok {
				for _, v := range vals {
					rr := &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
						Txt: []string{v},
					}
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeSOA:
			if d.inZone(name) {
				m.Answer = append(m.Answer, d.soa(q.Name))
			}
		case dns.TypeNS:
			if name == d.zone {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  d.ns,
				})
			}
		case dns.TypeA:
			if d.cfg.PublicIP != "" && (name == d.zone || name == d.ns) {
				if ip := parseIP4(d.cfg.PublicIP); ip != nil {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
						A:   ip,
					})
				}
			}
		}
	}

	if len(m.Answer) == 0 && d.inZone(canonicalFirst(r)) {
		// Authoritative negative answer: include SOA in authority section.
		m.Ns = append(m.Ns, d.soa(dns.Fqdn(d.cfg.Zone)))
	}

	if err := w.WriteMsg(m); err != nil {
		slog.Warn("dns write", "error", err)
	}
}

func canonicalFirst(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	return canonical(r.Question[0].Name)
}

func (d *DNSServer) inZone(name string) bool {
	return name == d.zone || strings.HasSuffix(name, "."+d.zone)
}

func (d *DNSServer) soa(name string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(d.cfg.Zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      d.ns,
		Mbox:    "hostmaster." + d.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  1,
	}
}

// Start launches the UDP and TCP listeners. It blocks until the first
// listener fails; run it in a goroutine.
func (d *DNSServer) Start() error {
	if d.cfg.Zone == "" {
		return fmt.Errorf("dns server: zone is required")
	}
	handler := dns.HandlerFunc(d.ServeDNS)

	d.udp = &dns.Server{Addr: d.cfg.Addr, Net: "udp", Handler: handler}
	d.tcp = &dns.Server{Addr: d.cfg.Addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 2)
	go func() { errCh <- d.udp.ListenAndServe() }()
	go func() { errCh <- d.tcp.ListenAndServe() }()

	slog.Info("authoritative DNS server listening",
		"addr", d.cfg.Addr, "zone", d.cfg.Zone, "ns", d.cfg.NSName)

	return <-errCh
}

// Shutdown stops both listeners.
func (d *DNSServer) Shutdown() {
	if d.udp != nil {
		_ = d.udp.Shutdown()
	}
	if d.tcp != nil {
		_ = d.tcp.Shutdown()
	}
}
