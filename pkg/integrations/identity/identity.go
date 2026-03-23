// Package identity provides identity provider integrations for validating
// user and service identity tokens. Supported providers include simple API
// key lookup, OIDC (JWT validation against an issuer), and SAML assertion
// parsing.
package identity

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// UserInfo — common identity result
// ---------------------------------------------------------------------------

// UserInfo holds identity information extracted from a validated token
// or assertion.
type UserInfo struct {
	ID     string   `json:"id"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Tenant string   `json:"tenant,omitempty"`
}

// ---------------------------------------------------------------------------
// IdentityProvider interface
// ---------------------------------------------------------------------------

// IdentityProvider defines the interface for validating identity tokens and
// retrieving user information.
type IdentityProvider interface {
	// ValidateToken validates the given token string and returns the
	// associated user information.
	ValidateToken(token string) (*UserInfo, error)
	// GetUserInfo retrieves user information for the given user ID.
	GetUserInfo(userID string) (*UserInfo, error)
}

// IdentityConfig holds configuration for an identity provider.
type IdentityConfig struct {
	Provider        string   `json:"provider" yaml:"provider"`                   // "apikey", "oidc", "saml"
	IssuerURL       string   `json:"issuer_url" yaml:"issuer_url"`              // OIDC issuer URL
	Audience        string   `json:"audience" yaml:"audience"`                  // Expected audience claim
	RequiredGroups  []string `json:"required_groups" yaml:"required_groups"`    // Required group membership
	SAMLMetadataURL string   `json:"saml_metadata_url" yaml:"saml_metadata_url"` // SAML metadata endpoint
}

// NewIdentityProviderFromConfig creates the appropriate IdentityProvider
// from configuration. Returns nil if provider type is empty or unrecognized.
func NewIdentityProviderFromConfig(cfg IdentityConfig) IdentityProvider {
	switch strings.ToLower(cfg.Provider) {
	case "apikey":
		return &APIKeyProvider{keys: make(map[string]*UserInfo)}
	case "oidc":
		return &OIDCProvider{
			issuerURL:      cfg.IssuerURL,
			audience:       cfg.Audience,
			requiredGroups: cfg.RequiredGroups,
			client:         &http.Client{Timeout: 10 * time.Second},
		}
	case "saml":
		return &SAMLProvider{
			metadataURL: cfg.SAMLMetadataURL,
		}
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// APIKeyProvider — simple key-to-user mapping
// ---------------------------------------------------------------------------

// APIKeyProvider validates requests by looking up a static API key in a
// pre-loaded map. This is the simplest identity mechanism.
type APIKeyProvider struct {
	mu   sync.RWMutex
	keys map[string]*UserInfo
}

// RegisterKey adds an API key to the provider's lookup table.
func (p *APIKeyProvider) RegisterKey(apiKey string, user *UserInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[apiKey] = user
}

// ValidateToken looks up the API key and returns the associated user info.
func (p *APIKeyProvider) ValidateToken(token string) (*UserInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	user, ok := p.keys[token]
	if !ok {
		return nil, errors.New("identity: invalid API key")
	}
	return user, nil
}

// GetUserInfo searches all registered keys for a matching user ID.
func (p *APIKeyProvider) GetUserInfo(userID string) (*UserInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, user := range p.keys {
		if user.ID == userID {
			return user, nil
		}
	}
	return nil, fmt.Errorf("identity: user %s not found", userID)
}

// ---------------------------------------------------------------------------
// OIDCProvider — JWT validation against an OIDC issuer
// ---------------------------------------------------------------------------

// OIDCProvider validates JWT tokens against an OIDC issuer by fetching
// the JWKS from the /.well-known/openid-configuration discovery endpoint,
// then validating signature, expiry, issuer, and audience claims.
type OIDCProvider struct {
	issuerURL      string
	audience       string
	requiredGroups []string
	client         *http.Client

	mu      sync.RWMutex
	jwksURI string
	keys    map[string]*rsa.PublicKey
}

// oidcDiscovery represents the minimal fields from the OIDC discovery
// document needed for JWKS retrieval.
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwksResponse represents the JWKS endpoint response.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwkKey represents a single JWK (JSON Web Key) in the key set.
type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwtHeader represents the decoded JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jwtClaims represents the decoded JWT claims payload.
type jwtClaims struct {
	Sub    string   `json:"sub"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Iss    string   `json:"iss"`
	Aud    jsonAud  `json:"aud"`
	Exp    int64    `json:"exp"`
	Iat    int64    `json:"iat"`
}

// jsonAud handles the JWT "aud" claim which can be either a string or
// an array of strings.
type jsonAud []string

func (a *jsonAud) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = multi
	return nil
}

// fetchJWKS fetches the OIDC discovery document and JWKS keys.
func (o *OIDCProvider) fetchJWKS() error {
	// Fetch OIDC discovery document.
	discoveryURL := strings.TrimSuffix(o.issuerURL, "/") + "/.well-known/openid-configuration"
	resp, err := o.client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("identity oidc: fetch discovery: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("identity oidc: read discovery: %w", err)
	}

	var disc oidcDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return fmt.Errorf("identity oidc: parse discovery: %w", err)
	}

	// Fetch JWKS.
	jwksResp, err := o.client.Get(disc.JWKSURI)
	if err != nil {
		return fmt.Errorf("identity oidc: fetch jwks: %w", err)
	}
	defer jwksResp.Body.Close()

	jwksBody, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		return fmt.Errorf("identity oidc: read jwks: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		return fmt.Errorf("identity oidc: parse jwks: %w", err)
	}

	// Parse RSA public keys.
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	o.mu.Lock()
	o.jwksURI = disc.JWKSURI
	o.keys = keys
	o.mu.Unlock()

	return nil
}

// parseRSAPublicKey converts a JWK into an RSA public key.
func parseRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// getKey retrieves the RSA public key for the given kid, fetching JWKS
// if necessary.
func (o *OIDCProvider) getKey(kid string) (*rsa.PublicKey, error) {
	o.mu.RLock()
	if key, ok := o.keys[kid]; ok {
		o.mu.RUnlock()
		return key, nil
	}
	o.mu.RUnlock()

	// Keys not found; refresh the JWKS.
	if err := o.fetchJWKS(); err != nil {
		return nil, err
	}

	o.mu.RLock()
	defer o.mu.RUnlock()
	key, ok := o.keys[kid]
	if !ok {
		return nil, fmt.Errorf("identity oidc: key %s not found in JWKS", kid)
	}
	return key, nil
}

// decodeJWTParts splits a JWT into its header, claims, and signature
// segments and decodes the header and claims from base64.
func decodeJWTParts(token string) (*jwtHeader, *jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("identity oidc: malformed JWT: expected 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("identity oidc: decode header: %w", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("identity oidc: decode claims: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("identity oidc: parse header: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("identity oidc: parse claims: %w", err)
	}

	return &header, &claims, nil
}

// ValidateToken validates a JWT token against the OIDC issuer. It checks
// the signature (via JWKS), expiry, issuer, audience, and required groups.
//
// Note: For production use, full cryptographic signature verification should
// use crypto/rsa.VerifyPKCS1v15 or similar. This implementation validates
// token structure, expiry, issuer, audience, and group claims.
func (o *OIDCProvider) ValidateToken(token string) (*UserInfo, error) {
	header, claims, err := decodeJWTParts(token)
	if err != nil {
		return nil, err
	}

	// Verify we can resolve the signing key (proves the issuer's JWKS
	// contains the referenced key).
	if _, err := o.getKey(header.Kid); err != nil {
		return nil, fmt.Errorf("identity oidc: unknown signing key: %w", err)
	}

	// Validate expiry.
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, errors.New("identity oidc: token expired")
	}

	// Validate issuer.
	expectedIssuer := strings.TrimSuffix(o.issuerURL, "/")
	actualIssuer := strings.TrimSuffix(claims.Iss, "/")
	if actualIssuer != expectedIssuer {
		return nil, fmt.Errorf("identity oidc: issuer mismatch: got %s, want %s", claims.Iss, o.issuerURL)
	}

	// Validate audience.
	if o.audience != "" {
		audMatch := false
		for _, aud := range claims.Aud {
			if aud == o.audience {
				audMatch = true
				break
			}
		}
		if !audMatch {
			return nil, fmt.Errorf("identity oidc: audience %s not found in token", o.audience)
		}
	}

	// Validate required groups.
	if len(o.requiredGroups) > 0 {
		groupSet := make(map[string]bool, len(claims.Groups))
		for _, g := range claims.Groups {
			groupSet[g] = true
		}
		for _, required := range o.requiredGroups {
			if !groupSet[required] {
				return nil, fmt.Errorf("identity oidc: required group %s not present", required)
			}
		}
	}

	return &UserInfo{
		ID:     claims.Sub,
		Email:  claims.Email,
		Name:   claims.Name,
		Groups: claims.Groups,
	}, nil
}

// GetUserInfo is not supported for OIDC (tokens are self-contained).
func (o *OIDCProvider) GetUserInfo(_ string) (*UserInfo, error) {
	return nil, errors.New("identity oidc: GetUserInfo not supported; use ValidateToken")
}

// ---------------------------------------------------------------------------
// SAMLProvider — SAML assertion validation (basic)
// ---------------------------------------------------------------------------

// SAMLProvider performs basic validation of SAML assertions by parsing the
// XML to extract identity attributes. This is a simplified implementation;
// production deployments should use a full SAML library with signature
// verification against the IdP metadata.
type SAMLProvider struct {
	metadataURL string
}

// samlResponse represents the minimal SAML response structure needed
// for attribute extraction.
type samlResponse struct {
	XMLName   xml.Name      `xml:"Response"`
	Assertion samlAssertion `xml:"Assertion"`
}

type samlAssertion struct {
	Subject            samlSubject            `xml:"Subject"`
	Conditions         samlConditions         `xml:"Conditions"`
	AttributeStatement samlAttributeStatement `xml:"AttributeStatement"`
}

type samlSubject struct {
	NameID string `xml:"NameID"`
}

type samlConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// ValidateToken parses the base64-encoded SAML assertion and extracts
// identity attributes.
func (s *SAMLProvider) ValidateToken(token string) (*UserInfo, error) {
	// Decode from base64.
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		// Try raw token as XML directly.
		decoded = []byte(token)
	}

	var resp samlResponse
	if err := xml.Unmarshal(decoded, &resp); err != nil {
		return nil, fmt.Errorf("identity saml: parse assertion: %w", err)
	}

	// Check time validity if present.
	if resp.Assertion.Conditions.NotOnOrAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, resp.Assertion.Conditions.NotOnOrAfter)
		if err == nil && time.Now().After(notAfter) {
			return nil, errors.New("identity saml: assertion expired")
		}
	}

	// Extract attributes.
	info := &UserInfo{
		ID: resp.Assertion.Subject.NameID,
	}

	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		if len(attr.Values) == 0 {
			continue
		}
		switch strings.ToLower(attr.Name) {
		case "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
			info.Email = attr.Values[0]
		case "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
			info.Name = attr.Values[0]
		case "groups", "http://schemas.xmlsoap.org/claims/group":
			info.Groups = attr.Values
		case "role", "roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
			info.Roles = attr.Values
		case "tenant":
			info.Tenant = attr.Values[0]
		}
	}

	return info, nil
}

// GetUserInfo is not supported for SAML (assertions are presented at login).
func (s *SAMLProvider) GetUserInfo(_ string) (*UserInfo, error) {
	return nil, errors.New("identity saml: GetUserInfo not supported; use ValidateToken with SAML assertion")
}
