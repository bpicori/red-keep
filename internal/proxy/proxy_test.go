package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// MatchDomain unit tests
// ---------------------------------------------------------------------------

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		want    bool
	}{
		// Exact match.
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},
		{"example.com", "EXAMPLE.COM", true},

		// No match.
		{"example.com", "other.com", false},
		{"example.com", "sub.example.com", false},

		// Wildcard match.
		{"sub.example.com", "*.example.com", true},
		{"a.b.example.com", "*.example.com", true},
		{"SUB.EXAMPLE.COM", "*.example.com", true},

		// Wildcard does NOT match the base domain.
		{"example.com", "*.example.com", false},

		// Wildcard on different domain.
		{"sub.other.com", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.domain, tt.pattern), func(t *testing.T) {
			got := MatchDomain(tt.domain, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchDomain(%q, %q) = %v, want %v", tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DomainAllowed unit tests
// ---------------------------------------------------------------------------

func TestDomainAllowed_Allowlist(t *testing.T) {
	p := New([]string{"example.com", "*.github.com"}, nil)

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"api.github.com", true},
		{"evil.com", false},
		{"github.com", false}, // wildcard doesn't match base
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := p.DomainAllowed(tt.domain); got != tt.want {
				t.Errorf("DomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainAllowed_Denylist(t *testing.T) {
	p := New(nil, []string{"evil.com", "*.malware.net"})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"github.com", true},
		{"evil.com", false},
		{"sub.malware.net", false},
		{"malware.net", true}, // wildcard doesn't match base
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := p.DomainAllowed(tt.domain); got != tt.want {
				t.Errorf("DomainAllowed(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainAllowed_NoRules(t *testing.T) {
	p := New(nil, nil)
	if !p.DomainAllowed("anything.com") {
		t.Error("expected all domains allowed when no rules configured")
	}
}

func TestDomainAllowed_TrailingDot(t *testing.T) {
	p := New([]string{"example.com"}, nil)
	// DNS names sometimes have a trailing dot.
	if !p.DomainAllowed("example.com.") {
		t.Error("expected trailing-dot domain to be allowed")
	}
}

// ---------------------------------------------------------------------------
// Proxy integration tests (HTTP)
// ---------------------------------------------------------------------------

func TestProxy_AllowlistHTTP(t *testing.T) {
	// Start a target HTTP server.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)

	// Start the filtering proxy allowing only the target host.
	prx := New([]string{targetURL.Hostname()}, nil)
	addr, err := prx.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		prx.Stop(ctx)
	}()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Allowed request should succeed.
	resp, err := client.Get(target.URL + "/allowed")
	if err != nil {
		t.Fatalf("expected request to succeed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "OK" {
		t.Errorf("expected body %q, got %q", "OK", string(body))
	}
}

func TestProxy_AllowlistBlocksHTTP(t *testing.T) {
	// Start a target HTTP server.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	// Start proxy allowing only "allowed.example.com" (not the target).
	prx := New([]string{"allowed.example.com"}, nil)
	addr, err := prx.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		prx.Stop(ctx)
	}()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	// Target host is not in the allowlist, so the proxy should return 403.
	resp, err := client.Get(target.URL + "/blocked")
	if err != nil {
		t.Fatalf("expected response (403), got error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_DenylistHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)

	// Deny the target host.
	prx := New(nil, []string{targetURL.Hostname()})
	addr, err := prx.Start()
	if err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		prx.Stop(ctx)
	}()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(target.URL + "/denied")
	if err != nil {
		t.Fatalf("expected response (403), got error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_StartStop(t *testing.T) {
	prx := New(nil, nil)
	addr, err := prx.Start()
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if addr == "" {
		t.Fatal("expected non-empty address")
	}
	if prx.Addr() != addr {
		t.Errorf("Addr() = %q, want %q", prx.Addr(), addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := prx.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// hostOnly helper
// ---------------------------------------------------------------------------

func TestHostOnly(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"[::1]:443", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := hostOnly(tt.in); got != tt.want {
				t.Errorf("hostOnly(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
