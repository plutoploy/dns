package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
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
	_ "modernc.org/sqlite"
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
// ManualDNSProvider – a DNS-01 provider that lets the user set the record
// externally, then resumes when confirmed.
// ---------------------------------------------------------------------------

// PendingChallenge holds the details of a DNS-01 challenge waiting for the
// user to set the TXT record.
type PendingChallenge struct {
	Domain  string `json:"domain"`
	FQDN    string `json:"fqdn"`  // _acme-challenge.<domain>.
	Value   string `json:"value"` // TXT record value (SHA-256 digest of keyAuth, base64url)
	Token   string `json:"token"`
	KeyAuth string `json:"key_authorization"`
}

// Store persists DNS-01 challenge tokens in SQLite.
type Store struct {
	db *sql.DB
}

// NewStore opens (or creates) the SQLite database at dsn.
func NewStore(dsn string) (*Store, error) {
	if dsn == "" {
		dsn = "./acme.db"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS challenges (
		domain    TEXT PRIMARY KEY,
		fqdn      TEXT NOT NULL,
		value     TEXT NOT NULL,
		token     TEXT NOT NULL,
		key_auth  TEXT NOT NULL,
		status    TEXT NOT NULL DEFAULT 'pending',
		created_at TEXT DEFAULT CURRENT_TIMESTAMP,
		updated_at TEXT DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}
	return &Store{db: db}, nil
}

// SaveChallenge upserts a challenge record.
func (s *Store) SaveChallenge(ctx context.Context, pc *PendingChallenge) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges (domain, fqdn, value, token, key_auth, status)
		 VALUES (?, ?, ?, ?, ?, 'pending')
		 ON CONFLICT(domain) DO UPDATE SET
		   fqdn=excluded.fqdn, value=excluded.value, token=excluded.token,
		   key_auth=excluded.key_auth, status='pending', updated_at=CURRENT_TIMESTAMP`,
		pc.Domain, pc.FQDN, pc.Value, pc.Token, pc.KeyAuth)
	return err
}

// RemoveChallenge deletes a challenge record.
func (s *Store) RemoveChallenge(ctx context.Context, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE domain = ?`, domain)
	return err
}

// GetChallenge retrieves a saved challenge.
func (s *Store) GetChallenge(ctx context.Context, domain string) (*PendingChallenge, error) {
	var pc PendingChallenge
	err := s.db.QueryRowContext(ctx,
		`SELECT domain, fqdn, value, token, key_auth FROM challenges WHERE domain = ?`, domain,
	).Scan(&pc.Domain, &pc.FQDN, &pc.Value, &pc.Token, &pc.KeyAuth)
	if err != nil {
		return nil, err
	}
	return &pc, nil
}

// Close shuts down the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// ManualDNSProvider implements challenge.Provider.
//
// Present saves the DNS-01 challenge token to the SQLite store, then blocks
// until Confirm() is called. You only put a CNAME record — the TXT value
// is in the DB for your DNS server or agent to read.
type ManualDNSProvider struct {
	mu        sync.Mutex
	pending   *PendingChallenge
	confirmCh chan struct{}
	store     *Store
}

func NewManualDNSProvider(store *Store) *ManualDNSProvider {
	return &ManualDNSProvider{store: store}
}

// Present stores the challenge info, upserts it into SQLite, and blocks
// until Confirm() is called.
func (p *ManualDNSProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)

	pc := &PendingChallenge{
		Domain:  domain,
		FQDN:    info.FQDN,
		Value:   info.Value,
		Token:   token,
		KeyAuth: keyAuth,
	}

	// Persist to SQLite so external agents can read it.
	if err := p.store.SaveChallenge(ctx, pc); err != nil {
		slog.Warn("save challenge to db", "domain", domain, "error", err)
	}

	p.mu.Lock()
	p.pending = pc
	ch := make(chan struct{})
	p.confirmCh = ch
	p.mu.Unlock()

	// Block until the user confirms (after creating the CNAME).
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CleanUp removes any pending challenge state and deletes the DB record.
func (p *ManualDNSProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending != nil && p.pending.Token == token {
		p.pending = nil
	}
	if err := p.store.RemoveChallenge(ctx, domain); err != nil {
		slog.Warn("remove challenge from db", "domain", domain, "error", err)
	}
	return nil
}

// Pending returns the current pending challenge, if any.
func (p *ManualDNSProvider) Pending() *PendingChallenge {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
}

// Confirm unblocks the Present call so that the ACME flow continues.
func (p *ManualDNSProvider) Confirm() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.confirmCh != nil {
		close(p.confirmCh)
		p.confirmCh = nil
	}
}

// Timeout implements challenge.ProviderTimeout (optional).
func (p *ManualDNSProvider) Timeout() (time.Duration, time.Duration) {
	return 5 * time.Minute, 5 * time.Second
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

	// DSN is the SQLite database path for persisting challenge tokens.
	// Defaults to "./acme.db".
	DSN string

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
// DomainChallenge
// ---------------------------------------------------------------------------

// DomainChallenge holds all DNS-01 challenge details returned to the caller.
type DomainChallenge struct {
	Domain string `json:"domain"`
	FQDN   string `json:"fqdn"`
	Value  string `json:"value"`
	Token  string `json:"token"`
	Status string `json:"status"` // pending | valid | invalid
	Error  string `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

// VerificationResult is the outcome of a completed domain verification.
type VerificationResult struct {
	Domain string `json:"domain"`
	Status string `json:"status"` // valid | invalid
	Error  string `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

// Verifier manages ACME accounts and DNS-01 domain verification.
type Verifier struct {
	config   VerifierConfig
	user     *AcmeUser
	client   *lego.Client
	provider *ManualDNSProvider
	store    *Store
	account  *AccountInfo

	mu           sync.Mutex
	pendingVerif map[string]*pendingVerification // domain -> verification
}

type pendingVerification struct {
	domain string
	certCh chan *certificate.Resource
	errCh  chan error
	done   bool
}

// NewVerifier creates an ACME verifier. The account is not registered until
// RegisterAccount is called.
func NewVerifier(cfg VerifierConfig) *Verifier {
	cfg.fill()
	store, err := NewStore(cfg.DSN)
	if err != nil {
		slog.Warn("acme store unavailable, challenges will not persist", "error", err)
	}
	return &Verifier{
		config:       cfg,
		store:        store,
		provider:     NewManualDNSProvider(store),
		pendingVerif: make(map[string]*pendingVerification),
	}
}

// ---------------------------------------------------------------------------
// Account registration
// ---------------------------------------------------------------------------

// RegisterAccount registers (or resolves) an ACME account with the CA.
// After a successful registration the verifier is ready for domain challenges.
func (v *Verifier) RegisterAccount(ctx context.Context) (*AccountInfo, error) {
	// Generate private key.
	key, err := generatePrivateKey(v.config.KeyType)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	v.user = &AcmeUser{
		email: v.config.Email,
		key:   key,
	}

	// Build lego config.
	legoCfg := lego.NewConfig(v.user)
	legoCfg.CADirURL = v.config.DirectoryURL
	legoCfg.HTTPClient = v.config.HTTPClient

	// Create the client.
	cl, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("create lego client: %w", err)
	}
	v.client = cl

	// Set our manual DNS-01 provider.
	if err := v.client.Challenge.SetDNS01Provider(v.provider); err != nil {
		return nil, fmt.Errorf("set DNS-01 provider: %w", err)
	}

	// Register (or resolve existing) account.
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

	slog.Info("ACME account registered",
		"email", info.Email,
		"uri", info.URI,
	)

	return info, nil
}

// Account returns the current registered account info, or nil.
func (v *Verifier) Account() *AccountInfo {
	return v.account
}

// ---------------------------------------------------------------------------
// Domain verification – DNS-01
// ---------------------------------------------------------------------------

// StartVerification creates a certificate order for the given domain and
// returns the DNS-01 challenge details needed to prove ownership.
//
// The caller should set the TXT record at the returned FQDN with the returned
// value, then call CompleteVerification.
func (v *Verifier) StartVerification(ctx context.Context, domain string) (*DomainChallenge, error) {
	if v.client == nil {
		return nil, errors.New("verifier: account not registered; call RegisterAccount first")
	}

	v.mu.Lock()
	if _, exists := v.pendingVerif[domain]; exists {
		v.mu.Unlock()
		return nil, fmt.Errorf("verification already in progress for %s", domain)
	}

	pv := &pendingVerification{
		domain: domain,
		certCh: make(chan *certificate.Resource, 1),
		errCh:  make(chan error, 1),
	}
	v.pendingVerif[domain] = pv
	v.mu.Unlock()

	// Kick off the ACME certificate obtain in a goroutine.
	// It will call our manual DNS provider's Present(), which blocks until
	// the user confirms the TXT record.
	go func() {
		res, err := v.client.Certificate.Obtain(ctx, certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		})
		if err != nil {
			pv.errCh <- err
			return
		}
		pv.certCh <- res
	}()

	// Wait for the provider to receive the challenge info and block.
	// We poll for the Pending value with a short timeout.
	time.Sleep(500 * time.Millisecond) // give Present a moment to run

	pending := v.provider.Pending()
	if pending == nil {
		// Check if the goroutine already failed.
		select {
		case err := <-pv.errCh:
			v.mu.Lock()
			delete(v.pendingVerif, domain)
			v.mu.Unlock()
			return nil, fmt.Errorf("obtain certificate: %w", err)
		default:
			// Still waiting…
			pending = v.provider.Pending()
			if pending == nil {
				return nil, errors.New("internal: challenge info not ready")
			}
		}
	}

	challenge := &DomainChallenge{
		Domain: domain,
		FQDN:   pending.FQDN,
		Value:  pending.Value,
		Token:  pending.Token,
		Status: "pending",
	}

	slog.Info("DNS-01 challenge ready",
		"domain", domain,
		"fqdn", pending.FQDN,
	)

	return challenge, nil
}

// CompleteVerification confirms that the DNS TXT record has been set and
// completes the ACME challenge, returning the result.
//
// This will block until the ACME CA validates the challenge (typically a few
// seconds to a minute).
func (v *Verifier) CompleteVerification(ctx context.Context, domain string) (*VerificationResult, error) {
	v.mu.Lock()
	pv, exists := v.pendingVerif[domain]
	if !exists {
		v.mu.Unlock()
		return nil, fmt.Errorf("no pending verification for %s", domain)
	}
	v.mu.Unlock()

	// Signal the provider to unblock Present().
	v.provider.Confirm()

	// Wait for the ACME result.
	var (
		cert *certificate.Resource
		err  error
	)

	select {
	case cert = <-pv.certCh:
	case err = <-pv.errCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	v.mu.Lock()
	delete(v.pendingVerif, domain)
	v.mu.Unlock()

	if err != nil {
		slog.Warn("DNS-01 verification failed", "domain", domain, "error", err)
		return &VerificationResult{
			Domain: domain,
			Status: "invalid",
			Error:  err.Error(),
		}, nil
	}

	slog.Info("DNS-01 verification succeeded", "domain", domain,
		"cert_url", cert.CertURL,
	)

	return &VerificationResult{
		Domain: domain,
		Status: "valid",
	}, nil
}

// VerificationStatus returns the current status of a domain verification.
func (v *Verifier) VerificationStatus(domain string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if pv, ok := v.pendingVerif[domain]; ok && !pv.done {
		return "pending"
	}
	return ""
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

// CloseStore shuts down the persistent store (call on server shutdown).
func (v *Verifier) CloseStore() error {
	if v.store != nil {
		return v.store.Close()
	}
	return nil
}

// LoadChallenge retrieves a previously-saved challenge from the store.
func LoadChallenge(ctx context.Context, store *Store, domain string) (*PendingChallenge, error) {
	if store == nil {
		return nil, errors.New("store not available")
	}
	return store.GetChallenge(ctx, domain)
}
