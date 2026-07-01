package main

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
	"plutoploy/dns-manager/acme"
)

func main() {
	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})
	acmeCfg := acme.VerifierConfig{
		DirectoryURL: os.Getenv("ACME_DIRECTORY_URL"),
		Email:        os.Getenv("ACME_ACCOUNT_EMAIL"),
		DSN:          os.Getenv("ACME_DB"),
	}
	verifier := acme.NewVerifier(acmeCfg)
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
