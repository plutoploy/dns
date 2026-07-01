package store

import (
	"os"
	"path/filepath"
	"testing"
)

func tempDB(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAccountCRUD(t *testing.T) {
	s := tempDB(t)

	err := s.SaveAccount("user@example.com", "https://acme-v02.api.letsencrypt.org/acme/acct/123", "https://acme-v02.api.letsencrypt.org/directory", "private-key-pem")
	if err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	a, err := s.GetAccount("user@example.com", "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if a.Email != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", a.Email)
	}
	if a.URI != "https://acme-v02.api.letsencrypt.org/acme/acct/123" {
		t.Errorf("uri = %q, want acme URI", a.URI)
	}
	if a.PrivateKey != "private-key-pem" {
		t.Errorf("private_key = %q, want private-key-pem", a.PrivateKey)
	}

	// Upsert
	err = s.SaveAccount("user@example.com", "https://acme-v02.api.letsencrypt.org/acme/acct/456", "https://acme-v02.api.letsencrypt.org/directory", "new-key")
	if err != nil {
		t.Fatalf("SaveAccount upsert: %v", err)
	}
	a, err = s.GetAccount("user@example.com", "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatalf("GetAccount after upsert: %v", err)
	}
	if a.URI != "https://acme-v02.api.letsencrypt.org/acme/acct/456" {
		t.Errorf("uri after upsert = %q, want .../acct/456", a.URI)
	}

	// List
	accounts, err := s.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 {
		t.Errorf("len(accounts) = %d, want 1", len(accounts))
	}
}

func TestDomainCRUD(t *testing.T) {
	s := tempDB(t)

	err := s.SaveDomain("example.com", "example-com.auth.example.com")
	if err != nil {
		t.Fatalf("SaveDomain: %v", err)
	}

	d, err := s.GetDomain("example.com")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if d.CNameTarget != "example-com.auth.example.com" {
		t.Errorf("cname_target = %q, want example-com.auth.example.com", d.CNameTarget)
	}

	// Upsert
	err = s.SaveDomain("example.com", "new-target.auth.example.com")
	if err != nil {
		t.Fatalf("SaveDomain upsert: %v", err)
	}
	d, err = s.GetDomain("example.com")
	if err != nil {
		t.Fatalf("GetDomain after upsert: %v", err)
	}
	if d.CNameTarget != "new-target.auth.example.com" {
		t.Errorf("cname_target after upsert = %q, want new-target.auth.example.com", d.CNameTarget)
	}

	// List
	domains, err := s.ListDomains()
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(domains) != 1 {
		t.Errorf("len(domains) = %d, want 1", len(domains))
	}
}

func TestCertCRUD(t *testing.T) {
	s := tempDB(t)

	err := s.SaveDomain("example.com", "example-com.auth.example.com")
	if err != nil {
		t.Fatalf("SaveDomain: %v", err)
	}

	err = s.SaveCertificate("example.com", "cert-pem", "key-pem", "issuer-pem", "https://example.com/cert/1", "valid")
	if err != nil {
		t.Fatalf("SaveCertificate: %v", err)
	}

	certs, err := s.ListCertificates("example.com")
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if certs[0].Certificate != "cert-pem" {
		t.Errorf("certificate = %q, want cert-pem", certs[0].Certificate)
	}
	if certs[0].Status != "valid" {
		t.Errorf("status = %q, want valid", certs[0].Status)
	}

	// List all
	allCerts, err := s.ListCertificates("")
	if err != nil {
		t.Fatalf("ListCertificates(all): %v", err)
	}
	if len(allCerts) != 1 {
		t.Errorf("len(allCerts) = %d, want 1", len(allCerts))
	}
}

func TestNewCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("database file not created")
	}
}
