package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

// ---------------------------------------------------------------------------
// User – implements registration.User for lego
// ---------------------------------------------------------------------------

// AcmeUser implements the lego registration.User interface.
type AcmeUser struct {
	email string
	key   crypto.Signer
	reg   *acme.ExtendedAccount
}

func (u *AcmeUser) GetEmail() string                       { return u.email }
func (u *AcmeUser) GetRegistration() *acme.ExtendedAccount { return u.reg }
func (u *AcmeUser) GetPrivateKey() crypto.Signer           { return u.key }

// ---------------------------------------------------------------------------
// AutoDNSProvider – fully automated DNS-01 provider.
//
// Present writes the ACME challenge TXT value directly into the authoritative
// DNS server's TXTStore. Because the user has delegated their
// _acme-challenge.<domain> record to our zone with a single static CNAME, the
// CA follows that CNAME to our server and reads the value we just wrote.
//
// No manual steps, no per-issuance record changes: only one CNAME per domain,
// configured once.
// ---------------------------------------------------------------------------

type AutoDNSProvider struct {
	dnsServer *DNSServer
	store     *TXTStore
}

func NewAutoDNSProvider(dnsServer *DNSServer, store *TXTStore) *AutoDNSProvider {
	return &AutoDNSProvider{dnsServer: dnsServer, store: store}
}

// Present is called by lego with the challenge. It records the TXT value at
// the delegation target so the CA can validate it.
func (p *AutoDNSProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)

	// Where the CA will actually look after following the user's CNAME.
	target := p.dnsServer.ChallengeFQDN(domain)

	// Serve the TXT value at the delegation target.
	p.store.Add(target, info.Value)

	slog.Info("DNS-01 present (automated)",
		"domain", domain,
		"challenge_fqdn", info.FQDN,
		"served_at", target,
	)
	return nil
}

// CleanUp removes the TXT value once validation is complete.
func (p *AutoDNSProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	target := p.dnsServer.ChallengeFQDN(domain)
	p.store.Remove(target)
	slog.Info("DNS-01 cleanup", "domain", domain, "served_at", target)
	return nil
}

// Timeout controls how long lego waits for the record to propagate and how
// often it polls. Because we serve the record ourselves, propagation is
// instant, but we still allow time for the CA's recursive resolver.
func (p *AutoDNSProvider) Timeout() (time.Duration, time.Duration) {
	return 3 * time.Minute, 5 * time.Second
}

// ---------------------------------------------------------------------------
// VerifierConfig
// ---------------------------------------------------------------------------

// KeyType enumerates supported private-key algorithms for the ACME account.
type KeyType string

const (
	KeyTypeEC256   KeyType = "EC256"
	KeyTypeRSA4096 KeyType = "RSA4096"
)

// VerifierConfig configures the ACME account verifier.
type VerifierConfig struct {
	// DirectoryURL is the ACME directory URL (e.g. Let's Encrypt, ZeroSSL).
	// If empty, defaults to Let's Encrypt production.
	DirectoryURL string

	// Email for the ACME account (required for registration).
	Email string

	// KeyType is the type of private key to generate for the account.
	// Defaults to EC256.
	KeyType KeyType

	// Delegation DNS zone this service is authoritative for, e.g.
	// "auth.example.com". Users CNAME their _acme-challenge record here.
	DNSZone string

	// DNSListen is the listen address for the authoritative DNS server.
	// Defaults to ":53".
	DNSListen string

	// DNSNSName is the nameserver hostname (SOA/NS). Defaults to "ns1.<zone>".
	DNSNSName string

	// PublicIP is served as an A record for the NS name / zone apex. Optional.
	PublicIP string

	// HTTPClient is an optional HTTP client. A default is used when nil.
	HTTPClient *http.Client
}

func (c *VerifierConfig) fill() {
	if c.DirectoryURL == "" {
		c.DirectoryURL = lego.DirectoryURLLetsEncrypt
	}
	if c.KeyType == "" {
		c.KeyType = KeyTypeEC256
	}
	if c.DNSListen == "" {
		c.DNSListen = ":53"
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 2 * time.Minute}
	}
}

// ---------------------------------------------------------------------------
// AccountInfo
// ---------------------------------------------------------------------------

// AccountInfo describes a registered ACME account.
type AccountInfo struct {
	Email string `json:"email"`
	URI   string `json:"uri"`
	CA    string `json:"ca"`
}

// ---------------------------------------------------------------------------
// CertificateResult
// ---------------------------------------------------------------------------

// CertificateResult holds the issued certificate material.
type CertificateResult struct {
	Domain            string `json:"domain"`
	Status            string `json:"status"` // valid | invalid
	Certificate       string `json:"certificate,omitempty"`
	PrivateKey        string `json:"private_key,omitempty"`
	IssuerCertificate string `json:"issuer_certificate,omitempty"`
	CertURL           string `json:"cert_url,omitempty"`
	Error             string `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

// Verifier manages the ACME account, the authoritative DNS server, and
// fully-automated DNS-01 certificate issuance.
type Verifier struct {
	config    VerifierConfig
	user      *AcmeUser
	client    *lego.Client
	provider  *AutoDNSProvider
	dnsServer *DNSServer
	txtStore  *TXTStore
	account   *AccountInfo

	mu sync.Mutex
}

// NewVerifier creates an ACME verifier and its authoritative DNS server.
// The DNS server is started with StartDNS; the account is registered with
// RegisterAccount.
func NewVerifier(cfg VerifierConfig) *Verifier {
	cfg.fill()

	txtStore := NewTXTStore()
	dnsServer := NewDNSServer(DNSServerConfig{
		Zone:     cfg.DNSZone,
		Addr:     cfg.DNSListen,
		NSName:   cfg.DNSNSName,
		PublicIP: cfg.PublicIP,
	}, txtStore)

	return &Verifier{
		config:    cfg,
		txtStore:  txtStore,
		dnsServer: dnsServer,
		provider:  NewAutoDNSProvider(dnsServer, txtStore),
	}
}

// StartDNS launches the authoritative DNS server. Run in a goroutine; it
// blocks until the server stops.
func (v *Verifier) StartDNS() error {
	return v.dnsServer.Start()
}

// ShutdownDNS stops the authoritative DNS server.
func (v *Verifier) ShutdownDNS() {
	v.dnsServer.Shutdown()
}

// CNAMETarget returns the one-time CNAME value the user must configure for a
// domain: _acme-challenge.<domain>  CNAME  <target>
func (v *Verifier) CNAMETarget(domain string) string {
	return v.dnsServer.CNAMETarget(domain)
}

// ---------------------------------------------------------------------------
// Account registration
// ---------------------------------------------------------------------------

// RegisterAccount registers (or resolves) an ACME account with the CA.
func (v *Verifier) RegisterAccount(ctx context.Context) (*AccountInfo, error) {
	key, err := generatePrivateKey(v.config.KeyType)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	v.user = &AcmeUser{email: v.config.Email, key: key}

	legoCfg := lego.NewConfig(v.user)
	legoCfg.CADirURL = v.config.DirectoryURL
	legoCfg.HTTPClient = v.config.HTTPClient

	cl, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("create lego client: %w", err)
	}
	v.client = cl

	// Wire up the fully-automated DNS-01 provider. Disable lego's own
	// propagation pre-check against public resolvers is not needed here since
	// we serve the record directly; keep default behaviour for safety.
	if err := v.client.Challenge.SetDNS01Provider(v.provider); err != nil {
		return nil, fmt.Errorf("set DNS-01 provider: %w", err)
	}

	reg, err := v.client.Registration.Register(ctx, registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, fmt.Errorf("register account: %w", err)
	}
	v.user.reg = reg

	info := &AccountInfo{
		Email: v.config.Email,
		URI:   reg.Location,
		CA:    v.config.DirectoryURL,
	}
	v.account = info
	slog.Info("ACME account registered", "email", info.Email, "uri", info.URI)
	return info, nil
}

// Account returns the current registered account info, or nil.
func (v *Verifier) Account() *AccountInfo {
	return v.account
}

// ---------------------------------------------------------------------------
// Certificate issuance – fully automated DNS-01
// ---------------------------------------------------------------------------

// Obtain runs the entire DNS-01 flow end-to-end: it writes the challenge TXT
// value into our authoritative DNS server, waits for the CA to validate it via
// the user's static CNAME, and returns the issued certificate.
//
// The only prerequisite is the one-time CNAME:
//
//	_acme-challenge.<domain>.  CNAME  <CNAMETarget(domain)>.
func (v *Verifier) Obtain(ctx context.Context, domain string) (*CertificateResult, error) {
	if v.client == nil {
		return nil, errors.New("verifier: account not registered; call RegisterAccount first")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	res, err := v.client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	})
	if err != nil {
		slog.Warn("certificate issuance failed", "domain", domain, "error", err)
		return &CertificateResult{
			Domain: domain,
			Status: "invalid",
			Error:  err.Error(),
		}, nil
	}

	slog.Info("certificate issued", "domain", domain, "cert_url", res.CertURL)
	return &CertificateResult{
		Domain:            domain,
		Status:            "valid",
		Certificate:       string(res.Certificate),
		PrivateKey:        string(res.PrivateKey),
		IssuerCertificate: string(res.IssuerCertificate),
		CertURL:           res.CertURL,
	}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func generatePrivateKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case KeyTypeEC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}
