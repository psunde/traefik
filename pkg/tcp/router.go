package tcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/containous/traefik/v2/pkg/log"
)

// Router is a TCP router
type Router struct {
	routingTable      map[string]Handler
	httpForwarder     Handler
	httpsForwarder    Handler
	httpHandler       http.Handler
	httpsHandler      http.Handler
	httpsTLSConfig    *tls.Config // default TLS config
	catchAllNoTLS     Handler
	hostHTTPTLSConfig map[string]*tls.Config // TLS configs keyed by SNI
}

// ServeTCP forwards the connection to the right TCP/HTTP handler
func (r *Router) ServeTCP(conn WriteCloser) {
	// FIXME -- Check if ProxyProtocol changes the first bytes of the request

	if r.catchAllNoTLS != nil && len(r.routingTable) == 0 {
		r.catchAllNoTLS.ServeTCP(conn)
		return
	}

	var wildcardHandler Handler
	if target, ok := r.routingTable["*"]; ok {
		wildcardHandler = target
	}

	br := bufio.NewReader(conn)
	serverName, tls, peeked := clientHelloServerName(br)
	if !tls {
		// Because there is no SNI on STARTTLS we try if handler is an STARTTLSHandler
		if h, ok := wildcardHandler.(*STARTTLSHandler); ok {
			h.ServeTCP(r.GetConn(conn, peeked))
			return
		}

		switch {
		case r.catchAllNoTLS != nil:
			r.catchAllNoTLS.ServeTCP(r.GetConn(conn, peeked))
		case r.httpForwarder != nil:
			r.httpForwarder.ServeTCP(r.GetConn(conn, peeked))
		default:
			conn.Close()
		}
		return
	}

	// FIXME Optimize and test the routing table before helloServerName
	serverName = strings.ToLower(serverName)
	if r.routingTable != nil && serverName != "" {
		if target, ok := r.routingTable[serverName]; ok {
			target.ServeTCP(r.GetConn(conn, peeked))
			return
		}
	}

	// FIXME Needs tests
	if wildcardHandler != nil {
		wildcardHandler.ServeTCP(r.GetConn(conn, peeked))
		return
	}

	if r.httpsForwarder != nil {
		r.httpsForwarder.ServeTCP(r.GetConn(conn, peeked))
	} else {
		conn.Close()
	}
}

// AddRoute defines a handler for a given sniHost (* is the only valid option)
func (r *Router) AddRoute(sniHost string, target Handler) {
	if r.routingTable == nil {
		r.routingTable = map[string]Handler{}
	}
	r.routingTable[strings.ToLower(sniHost)] = target
}

// AddRouteTLS defines a handler for a given sniHost and sets the matching tlsConfig
func (r *Router) AddRouteTLS(sniHost string, target Handler, config *tls.Config) {
	r.AddRoute(sniHost, &TLSHandler{
		Next:   target,
		Config: config,
	})
}

// AddRouteSTARTTLS defines a handler for a given sniHost and sets the matching tlsConfig
func (r *Router) AddRouteSTARTTLS(sniHost, protocol string, target Handler, config *tls.Config) {
	r.AddRoute(sniHost, &STARTTLSHandler{
		Next:     target,
		Config:   config,
		Protocol: protocol,
	})
}

// AddRouteHTTPTLS defines a handler for a given sniHost and sets the matching tlsConfig
func (r *Router) AddRouteHTTPTLS(sniHost string, config *tls.Config) {
	if r.hostHTTPTLSConfig == nil {
		r.hostHTTPTLSConfig = map[string]*tls.Config{}
	}
	r.hostHTTPTLSConfig[sniHost] = config
}

// AddCatchAllNoTLS defines the fallback tcp handler
func (r *Router) AddCatchAllNoTLS(handler Handler) {
	r.catchAllNoTLS = handler
}

// GetConn creates a connection proxy with a peeked string
func (r *Router) GetConn(conn WriteCloser, peeked string) WriteCloser {
	// FIXME should it really be on Router ?
	conn = &Conn{
		Peeked:      []byte(peeked),
		WriteCloser: conn,
	}
	return conn
}

// GetHTTPHandler gets the attached http handler
func (r *Router) GetHTTPHandler() http.Handler {
	return r.httpHandler
}

// GetHTTPSHandler gets the attached https handler
func (r *Router) GetHTTPSHandler() http.Handler {
	return r.httpsHandler
}

// HTTPForwarder sets the tcp handler that will forward the connections to an http handler
func (r *Router) HTTPForwarder(handler Handler) {
	r.httpForwarder = handler
}

// HTTPSForwarder sets the tcp handler that will forward the TLS connections to an http handler
func (r *Router) HTTPSForwarder(handler Handler) {
	for sniHost, tlsConf := range r.hostHTTPTLSConfig {
		r.AddRouteTLS(sniHost, handler, tlsConf)
	}

	r.httpsForwarder = &TLSHandler{
		Next:   handler,
		Config: r.httpsTLSConfig,
	}
}

// HTTPHandler attaches http handlers on the router
func (r *Router) HTTPHandler(handler http.Handler) {
	r.httpHandler = handler
}

// HTTPSHandler attaches https handlers on the router
func (r *Router) HTTPSHandler(handler http.Handler, config *tls.Config) {
	r.httpsHandler = handler
	r.httpsTLSConfig = config
}

// Conn is a connection proxy that handles Peeked bytes
type Conn struct {
	// Peeked are the bytes that have been read from Conn for the
	// purposes of route matching, but have not yet been consumed
	// by Read calls. It set to nil by Read when fully consumed.
	Peeked []byte

	// Conn is the underlying connection.
	// It can be type asserted against *net.TCPConn or other types
	// as needed. It should not be read from directly unless
	// Peeked is nil.
	WriteCloser
}

// Read reads bytes from the connection (using the buffer prior to actually reading)
func (c *Conn) Read(p []byte) (n int, err error) {
	if len(c.Peeked) > 0 {
		n = copy(p, c.Peeked)
		c.Peeked = c.Peeked[n:]
		if len(c.Peeked) == 0 {
			c.Peeked = nil
		}
		return n, nil
	}
	return c.WriteCloser.Read(p)
}

// clientHelloServerName returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
// On any error, the empty string is returned.
func clientHelloServerName(br *bufio.Reader) (string, bool, string) {
	hdr, err := br.Peek(1)
	if err != nil {
		if err != io.EOF {
			log.Errorf("Error while Peeking first byte: %s", err)
		}
		return "", false, ""
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		// log.Errorf("Error not tls")
		return "", false, getPeeked(br) // Not TLS.
	}

	const recordHeaderLen = 5
	hdr, err = br.Peek(recordHeaderLen)
	if err != nil {
		log.Errorf("Error while Peeking hello: %s", err)
		return "", false, getPeeked(br)
	}

	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]
	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		log.Errorf("Error while Hello: %s", err)
		return "", true, getPeeked(br)
	}

	sni := ""
	server := tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	})
	_ = server.Handshake()

	return sni, true, getPeeked(br)
}

func getPeeked(br *bufio.Reader) string {
	peeked, err := br.Peek(br.Buffered())
	if err != nil {
		log.Errorf("Could not get anything: %s", err)
		return ""
	}
	return string(peeked)
}

// sniSniffConn is a net.Conn that reads from r, fails on Writes,
// and crashes otherwise.
type sniSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

// Read reads from the underlying reader
func (c sniSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write crashes all the time
func (sniSniffConn) Write(p []byte) (int, error) { return 0, io.EOF }
