package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// directTransport forwards HTTP requests without honouring system proxy
// env vars (which would cause an infinite loop since we ARE the proxy).
var directTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// BlockedHandler is called when the proxy blocks a request to a domain.
// domain is the hostname that was denied.
type BlockedHandler func(domain string)

// FilteringProxy is a forward HTTP/HTTPS proxy that enforces domain-based
// access control. It supports two modes:
//
//   - Allowlist: only connections to explicitly listed domains are permitted.
//   - Denylist: connections to listed domains are blocked; everything else passes.
//
// HTTPS is handled via the CONNECT method (tunnelling); the proxy inspects
// the target hostname but does NOT terminate TLS — the client negotiates
// TLS end-to-end through the tunnel.
type FilteringProxy struct {
	allowDomains []string
	denyDomains  []string

	// OnBlocked is called each time the proxy denies a request. Optional.
	OnBlocked BlockedHandler

	listener net.Listener
	server   *http.Server
}

// New creates a FilteringProxy with the given rules.
// When allowDomains is non-empty only those domains are permitted (allowlist).
// When denyDomains is non-empty those domains are blocked (denylist).
// Both lists support wildcards: "*.example.com" matches any subdomain.
func New(allowDomains, denyDomains []string) *FilteringProxy {
	return &FilteringProxy{
		allowDomains: normalizeDomains(allowDomains),
		denyDomains:  normalizeDomains(denyDomains),
	}
}

// Start begins listening on a random localhost port and returns the address
// in "host:port" form, suitable for use in HTTP_PROXY / HTTPS_PROXY.
func (p *FilteringProxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("proxy listen: %w", err)
	}
	p.listener = ln

	p.server = &http.Server{
		Handler: http.HandlerFunc(p.handleRequest),
	}

	go p.server.Serve(ln) //nolint:errcheck // returns ErrServerClosed on shutdown
	return ln.Addr().String(), nil
}

// Addr returns the proxy's listen address, or "" if not started.
func (p *FilteringProxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Stop gracefully shuts down the proxy.
func (p *FilteringProxy) Stop(ctx context.Context) error {
	if p.server == nil {
		return nil
	}
	return p.server.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

func (p *FilteringProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect processes HTTPS CONNECT tunnelling requests.
func (p *FilteringProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)

	if !p.DomainAllowed(host) {
		p.notifyBlocked(host)
		http.Error(w, fmt.Sprintf("red-keep: domain %q blocked by policy", host), http.StatusForbidden)
		return
	}

	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		targetConn.Close()
		return
	}

	// Bidirectional tunnel — when one direction hits EOF the write side
	// of the other connection is half-closed so the peer sees EOF too.
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copyDir(targetConn, clientConn)
	go copyDir(clientConn, targetConn)

	wg.Wait()
	clientConn.Close()
	targetConn.Close()
}

// handleHTTP forwards plain HTTP requests (non-CONNECT).
func (p *FilteringProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.URL.Host)
	if host == "" {
		host = hostOnly(r.Host)
	}

	if !p.DomainAllowed(host) {
		p.notifyBlocked(host)
		http.Error(w, fmt.Sprintf("red-keep: domain %q blocked by policy", host), http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""

	// Strip hop-by-hop headers that must not be forwarded.
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	resp, err := directTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// notifyBlocked calls the OnBlocked handler if one is configured.
func (p *FilteringProxy) notifyBlocked(domain string) {
	if p.OnBlocked != nil {
		p.OnBlocked(domain)
	}
}

// ---------------------------------------------------------------------------
// Domain matching
// ---------------------------------------------------------------------------

// DomainAllowed reports whether domain is permitted by the configured rules.
//
// Allowlist mode (allowDomains non-empty): the domain must match at least one
// entry; everything else is blocked.
//
// Denylist mode (denyDomains non-empty): the domain must NOT match any entry;
// everything else is allowed.
//
// When both lists are empty every domain is allowed.
func (p *FilteringProxy) DomainAllowed(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Allowlist mode: only explicitly allowed domains pass.
	if len(p.allowDomains) > 0 {
		for _, pattern := range p.allowDomains {
			if MatchDomain(domain, pattern) {
				return true
			}
		}
		return false
	}

	// Denylist mode: explicitly denied domains are blocked.
	if len(p.denyDomains) > 0 {
		for _, pattern := range p.denyDomains {
			if MatchDomain(domain, pattern) {
				return false
			}
		}
	}

	return true
}

// MatchDomain reports whether domain matches pattern.
//
// Supported patterns:
//   - "example.com"       — exact match (case-insensitive)
//   - "*.example.com"     — matches any subdomain (e.g. "a.example.com",
//     "x.y.example.com") but NOT "example.com" itself.
func MatchDomain(domain, pattern string) bool {
	domain = strings.ToLower(domain)
	pattern = strings.ToLower(pattern)

	if domain == pattern {
		return true
	}

	// Wildcard: *.example.com → suffix match on .example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		return strings.HasSuffix(domain, suffix)
	}

	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizeDomains lowercases and trims trailing dots from a list of domains.
func normalizeDomains(domains []string) []string {
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = strings.ToLower(strings.TrimSuffix(d, "."))
	}
	return out
}

// hostOnly strips the port from a "host:port" string.
// If the input has no port it is returned as-is.
func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}
