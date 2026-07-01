package acme

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type registerRequest struct {
	KeyType string `json:"key_type"`
}

type domainRequest struct {
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

// RegisterAccountHandler handles POST /acme/register
func (h *Handler) RegisterAccountHandler(c *gin.Context) {
	if h.Verifier == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{Error: "verifier not initialised"})
		return
	}

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

// SetupHandler handles POST /acme/setup
// It returns the one-time CNAME record the user must configure for a domain.
func (h *Handler) SetupHandler(c *gin.Context) {
	if h.Verifier == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{Error: "verifier not initialised"})
		return
	}

	var req domainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain": req.Domain,
		"cname": gin.H{
			"name":  "_acme-challenge." + req.Domain,
			"type":  "CNAME",
			"value": h.Verifier.CNAMETarget(req.Domain),
		},
		"instructions": "Create this CNAME record once. After it resolves, call POST /acme/issue to obtain the certificate. Renewals need no further DNS changes.",
	})
}

// IssueHandler handles POST /acme/issue
// It runs the fully-automated DNS-01 flow and returns the certificate.
func (h *Handler) IssueHandler(c *gin.Context) {
	if h.Verifier == nil || h.Verifier.Account() == nil {
		c.JSON(http.StatusPreconditionFailed, errorResponse{
			Error: "no ACME account registered; call /acme/register first",
		})
		return
	}

	var req domainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: err.Error()})
		return
	}

	result, err := h.Verifier.Obtain(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: err.Error()})
		return
	}

	if result.Status != "valid" {
		c.JSON(http.StatusBadGateway, gin.H{
			"domain": result.Domain,
			"status": result.Status,
			"error":  result.Error,
		})
		return
	}

	c.JSON(http.StatusOK, result)
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
	rg.POST("/setup", h.SetupHandler)
	rg.POST("/issue", h.IssueHandler)
	rg.GET("/account", h.AccountHandler)
}
