package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"plutoploy/dns-manager/acme"
	"plutoploy/dns-manager/store"
)

func main() {
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "dns-manager.db"
	}

	db, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	acmeCfg := acme.VerifierConfig{
		DirectoryURL: os.Getenv("ACME_DIRECTORY_URL"),
		Email:        os.Getenv("ACME_ACCOUNT_EMAIL"),
		DNSZone:      os.Getenv("ACME_DNS_ZONE"),
		DNSListen:    os.Getenv("ACME_DNS_LISTEN"),
		DNSNSName:    os.Getenv("ACME_DNS_NS"),
		PublicIP:     os.Getenv("ACME_PUBLIC_IP"),
	}
	verifier := acme.NewVerifier(acmeCfg, db)

	// Try to load a saved account from the database.
	if err := verifier.LoadAccount(context.Background()); err != nil {
		log.Printf("no saved account: %v", err)
	}

	// Start the authoritative DNS server that answers the delegated
	// _acme-challenge TXT queries. Required for the automated flow.
	if acmeCfg.DNSZone != "" {
		go func() {
			if err := verifier.StartDNS(); err != nil {
				log.Fatalf("dns server: %v", err)
			}
		}()
	} else {
		log.Println("warning: ACME_DNS_ZONE not set; automated DNS-01 disabled")
	}

	acmeGroup := r.Group("/acme")
	acme.SetupRoutes(acmeGroup, verifier)

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
