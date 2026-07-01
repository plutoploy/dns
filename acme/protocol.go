package acme

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type registerRequest struct {
	KeyType string `json:"key_type"`
}

type checkRequest struct {
	Domain string `json:"domain" binding:"required,fqdn"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type Handler struct {
	*Verifier
}

func NewHandler(v *Verifier) *Handler {
	return &Handler{Verifier: v}
}

func (h *Handler) RegisterAccountHandler(c *gin.Context) {
	if h.Verifier == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{
			Error: "verifier not initialised",
		})
		return
	}

	// If the request has a key_type, update the config (overrides env default).
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err == nil && req.KeyType != "" {
		h.Verifier.config.KeyType = KeyType(req.KeyType)
	}

	acc, err := h.Verifier.RegisterAccount(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, acc)
}

// StartVerificationHandler handles POST /acme/verify
// It returns the DNS-01 challenge details (FQDN and TXT value).
func (h *Handler) StartVerificationHandler(c *gin.Context) {
	if h.Verifier == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{
			Error: "no ACME account registered; call /acme/register first",
		})
		return
	}

	var req checkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	challenge, err := h.Verifier.StartVerification(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, challenge)
}

// CompleteVerificationHandler handles POST /acme/check
// It signals that the DNS TXT record has been set and waits for ACME validation.
func (h *Handler) CompleteVerificationHandler(c *gin.Context) {
	if h.Verifier == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{
			Error: "no ACME account registered; call /acme/register first",
		})
		return
	}

	var req checkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	result, err := h.Verifier.CompleteVerification(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	if result.Status != "valid" {
		c.JSON(http.StatusOK, gin.H{
			"domain": result.Domain,
			"status": result.Status,
			"error":  result.Error,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain": result.Domain,
		"status": result.Status,
	})
}

// StatusHandler handles GET /acme/status/:domain
func (h *Handler) StatusHandler(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "domain parameter required"})
		return
	}

	status := ""
	if h.Verifier != nil {
		status = h.Verifier.VerificationStatus(domain)
	}

	if status == "" {
		c.JSON(http.StatusOK, gin.H{
			"domain": domain,
			"status": "not_found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain": domain,
		"status": status,
	})
}

// AccountHandler handles GET /acme/account
func (h *Handler) AccountHandler(c *gin.Context) {
	if h.Verifier == nil || h.Verifier.Account() == nil {
		c.JSON(http.StatusNotFound, errorResponse{Error: "no account registered"})
		return
	}

	c.JSON(http.StatusOK, h.Verifier.Account())
}

// ---------------------------------------------------------------------------
// Route setup
// ---------------------------------------------------------------------------

// SetupRoutes adds ACME routes to a Gin engine group.
func SetupRoutes(rg *gin.RouterGroup, v *Verifier) {
	h := NewHandler(v)

	rg.POST("/register", h.RegisterAccountHandler)
	rg.POST("/verify", h.StartVerificationHandler)
	rg.POST("/check", h.CompleteVerificationHandler)
	rg.GET("/status/:domain", h.StatusHandler)
	rg.GET("/account", h.AccountHandler)
}
