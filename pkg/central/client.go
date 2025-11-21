package central

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	resultsv1alpha1 "github.com/kylape/stackrox-results-operator/api/v1alpha1"
)

var log = logf.Log.WithName("central-client")

// Client represents a client for connecting to StackRox Central
type Client struct {
	endpoint   string
	httpClient *http.Client
	auth       AuthProvider
	k8sClient  client.Client
}

// AuthProvider provides authentication credentials for Central API calls
type AuthProvider interface {
	// GetAuthHeader returns the Authorization header value
	GetAuthHeader(ctx context.Context) (string, error)
	// Refresh refreshes the authentication token if needed
	Refresh(ctx context.Context) error
}

// m2mAuthProvider implements AuthProvider using Kubernetes service account token exchange
type m2mAuthProvider struct {
	endpoint   string
	httpClient *http.Client
	token      string
	lastUpdate time.Time
}

// apiTokenAuthProvider implements AuthProvider using a static API token
type apiTokenAuthProvider struct {
	token string
}

// htpasswdAuthProvider implements AuthProvider using username/password
type htpasswdAuthProvider struct {
	username string
	password string
}

// noAuthProvider implements AuthProvider for unauthenticated requests
type noAuthProvider struct{}


// Config contains configuration for creating a Central client
type Config struct {
	Endpoint       string
	TLSConfig      *resultsv1alpha1.TLSConfig
	AuthSecretName string
	Namespace      string
	K8sClient      client.Client
}

// New creates a new Central API client
func New(ctx context.Context, config Config) (*Client, error) {
	// Build TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify {
		log.Info("WARNING: TLS verification is disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	// Load CA bundle if provided
	if config.TLSConfig != nil && config.TLSConfig.CABundleSecretName != "" {
		caCert, err := loadCABundle(ctx, config.K8sClient, config.Namespace, config.TLSConfig.CABundleSecretName)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load CA bundle")
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to append CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	// Determine auth provider
	authProvider, err := createAuthProvider(ctx, config, httpClient)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create auth provider")
	}

	// Perform initial authentication
	if err := authProvider.Refresh(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to authenticate with Central")
	}

	return &Client{
		endpoint:   config.Endpoint,
		httpClient: httpClient,
		auth:       authProvider,
		k8sClient:  config.K8sClient,
	}, nil
}

// createAuthProvider determines which authentication method to use
func createAuthProvider(ctx context.Context, config Config, httpClient *http.Client) (AuthProvider, error) {
	// If no auth secret is configured, use no authentication
	if config.AuthSecretName == "" {
		log.Info("No auth secret configured, using unauthenticated requests")
		return &noAuthProvider{}, nil
	}

	// Load auth secret
	secret := &corev1.Secret{}
	if err := config.K8sClient.Get(ctx, client.ObjectKey{
		Namespace: config.Namespace,
		Name:      config.AuthSecretName,
	}, secret); err != nil {
		return nil, errors.Wrap(err, "failed to get auth secret")
	}

	// Check for API token (preferred)
	if token, ok := secret.Data["token"]; ok {
		log.Info("Using API token authentication")
		return &apiTokenAuthProvider{token: string(token)}, nil
	}

	// Check for htpasswd (username/password)
	if username, hasUser := secret.Data["username"]; hasUser {
		if password, hasPass := secret.Data["password"]; hasPass {
			log.Info("Using htpasswd authentication")
			return &htpasswdAuthProvider{
				username: string(username),
				password: string(password),
			}, nil
		}
	}

	// Fall back to m2m (service account token exchange)
	// This is used when running in-cluster without explicit credentials
	log.Info("Using machine-to-machine (service account) authentication")
	return &m2mAuthProvider{
		endpoint:   config.Endpoint,
		httpClient: httpClient,
	}, nil
}

// loadCABundle loads CA certificate from a secret
func loadCABundle(ctx context.Context, k8sClient client.Client, namespace, secretName string) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      secretName,
	}, secret); err != nil {
		return nil, err
	}

	caCert, ok := secret.Data["ca.crt"]
	if !ok {
		return nil, errors.New("ca.crt not found in secret")
	}

	return caCert, nil
}

// m2m authentication implementation

func (m *m2mAuthProvider) GetAuthHeader(ctx context.Context) (string, error) {
	// Refresh token if needed
	if time.Since(m.lastUpdate) > 60*time.Second {
		if err := m.Refresh(ctx); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("Bearer %s", m.token), nil
}

func (m *m2mAuthProvider) Refresh(ctx context.Context) error {
	log.V(1).Info("Refreshing Central API token via m2m exchange")

	// Read Kubernetes service account token
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return errors.Wrap(err, "failed to read service account token")
	}

	// Exchange service account token for Central API token
	// TODO: Implement actual token exchange API call
	// For now, this is a placeholder that would use Central's /v1/auth/m2m/exchange endpoint

	req, err := http.NewRequestWithContext(ctx, "POST", m.endpoint+"/v1/auth/m2m/exchange", nil)
	if err != nil {
		return errors.Wrap(err, "failed to create token exchange request")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(saToken)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "token exchange request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	// Parse response to get access token
	// TODO: Implement actual response parsing
	// For now, using placeholder

	m.token = "exchanged-token-placeholder"
	m.lastUpdate = time.Now()

	return nil
}

// API token authentication implementation

func (a *apiTokenAuthProvider) GetAuthHeader(ctx context.Context) (string, error) {
	return fmt.Sprintf("Bearer %s", a.token), nil
}

func (a *apiTokenAuthProvider) Refresh(ctx context.Context) error {
	// Static API tokens don't need refresh
	return nil
}

// htpasswd authentication implementation

func (h *htpasswdAuthProvider) GetAuthHeader(ctx context.Context) (string, error) {
	// Basic auth: base64(username:password)
	creds := fmt.Sprintf("%s:%s", h.username, h.password)
	encoded := base64.StdEncoding.EncodeToString([]byte(creds))
	return fmt.Sprintf("Basic %s", encoded), nil
}

func (h *htpasswdAuthProvider) Refresh(ctx context.Context) error {
	// Basic auth doesn't need refresh
	return nil
}

// No auth implementation

func (n *noAuthProvider) GetAuthHeader(ctx context.Context) (string, error) {
	// Return empty string for no authentication
	return "", nil
}

func (n *noAuthProvider) Refresh(ctx context.Context) error {
	// No auth doesn't need refresh
	return nil
}

// doRequest performs an authenticated HTTP request to Central
func (c *Client) doRequest(ctx context.Context, method, path string) (*http.Response, error) {
	url := c.endpoint + path

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	// Get auth header
	authHeader, err := c.auth.GetAuthHeader(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get auth header")
	}

	// Only set Authorization header if auth is configured
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}

	return resp, nil
}

// TestConnection tests the connection to Central
func (c *Client) TestConnection(ctx context.Context) error {
	log.Info("Testing connection to Central", "endpoint", c.endpoint)

	resp, err := c.doRequest(ctx, "GET", "/v1/ping")
	if err != nil {
		return errors.Wrap(err, "ping request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("ping failed with status %d", resp.StatusCode)
	}

	log.Info("Successfully connected to Central")
	return nil
}
