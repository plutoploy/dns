package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type AccountRow struct {
	ID         int64
	Email      string
	URI        string
	CA         string
	PrivateKey string
	CreatedAt  time.Time
}

type DomainRow struct {
	ID          int64
	Domain      string
	CNameTarget string
	CreatedAt   time.Time
}

type CertRow struct {
	ID          int64
	Domain      string
	Certificate string
	PrivateKey  string
	IssuerCert  string
	CertURL     string
	Status      string
	IssuedAt    time.Time
}

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS accounts (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			email       TEXT NOT NULL,
			uri         TEXT NOT NULL,
			ca          TEXT NOT NULL,
			private_key TEXT NOT NULL,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(email, ca)
		)`,
		`CREATE TABLE IF NOT EXISTS domains (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			domain       TEXT NOT NULL UNIQUE,
			cname_target TEXT NOT NULL,
			created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS certificates (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			domain       TEXT NOT NULL,
			certificate  TEXT NOT NULL,
			private_key  TEXT NOT NULL,
			issuer_cert  TEXT,
			cert_url     TEXT,
			status       TEXT NOT NULL DEFAULT 'valid',
			issued_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (domain) REFERENCES domains(domain)
		)`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("exec %q: %w", q[:40], err)
		}
	}
	return nil
}

func (s *Store) SaveAccount(email, uri, ca, privateKeyPEM string) error {
	_, err := s.db.Exec(
		`INSERT INTO accounts (email, uri, ca, private_key) VALUES (?, ?, ?, ?)
		 ON CONFLICT(email, ca) DO UPDATE SET uri=excluded.uri, private_key=excluded.private_key`,
		email, uri, ca, privateKeyPEM,
	)
	return err
}

func (s *Store) GetAccount(email, ca string) (*AccountRow, error) {
	row := s.db.QueryRow(
		`SELECT id, email, uri, ca, private_key, created_at FROM accounts WHERE email=? AND ca=?`,
		email, ca,
	)
	var a AccountRow
	if err := row.Scan(&a.ID, &a.Email, &a.URI, &a.CA, &a.PrivateKey, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) GetAccountByID(id int64) (*AccountRow, error) {
	row := s.db.QueryRow(
		`SELECT id, email, uri, ca, private_key, created_at FROM accounts WHERE id=?`, id,
	)
	var a AccountRow
	if err := row.Scan(&a.ID, &a.Email, &a.URI, &a.CA, &a.PrivateKey, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) ListAccounts() ([]AccountRow, error) {
	rows, err := s.db.Query(`SELECT id, email, uri, ca, private_key, created_at FROM accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AccountRow
	for rows.Next() {
		var a AccountRow
		if err := rows.Scan(&a.ID, &a.Email, &a.URI, &a.CA, &a.PrivateKey, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SaveDomain(domain, cnameTarget string) error {
	_, err := s.db.Exec(
		`INSERT INTO domains (domain, cname_target) VALUES (?, ?)
		 ON CONFLICT(domain) DO UPDATE SET cname_target=excluded.cname_target`,
		domain, cnameTarget,
	)
	return err
}

func (s *Store) GetDomain(domain string) (*DomainRow, error) {
	row := s.db.QueryRow(
		`SELECT id, domain, cname_target, created_at FROM domains WHERE domain=?`, domain,
	)
	var d DomainRow
	if err := row.Scan(&d.ID, &d.Domain, &d.CNameTarget, &d.CreatedAt); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) ListDomains() ([]DomainRow, error) {
	rows, err := s.db.Query(`SELECT id, domain, cname_target, created_at FROM domains`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainRow
	for rows.Next() {
		var d DomainRow
		if err := rows.Scan(&d.ID, &d.Domain, &d.CNameTarget, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SaveCertificate(domain, cert, key, issuerCert, certURL, status string) error {
	_, err := s.db.Exec(
		`INSERT INTO certificates (domain, certificate, private_key, issuer_cert, cert_url, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		domain, cert, key, issuerCert, certURL, status,
	)
	return err
}

func (s *Store) ListCertificates(domain string) ([]CertRow, error) {
	var rows *sql.Rows
	var err error
	if domain != "" {
		rows, err = s.db.Query(
			`SELECT id, domain, certificate, private_key, issuer_cert, cert_url, status, issued_at
			 FROM certificates WHERE domain=? ORDER BY issued_at DESC`, domain,
		)
	} else {
		rows, err = s.db.Query(
			`SELECT id, domain, certificate, private_key, issuer_cert, cert_url, status, issued_at
			 FROM certificates ORDER BY issued_at DESC`,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CertRow
	for rows.Next() {
		var c CertRow
		if err := rows.Scan(&c.ID, &c.Domain, &c.Certificate, &c.PrivateKey, &c.IssuerCert, &c.CertURL, &c.Status, &c.IssuedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
