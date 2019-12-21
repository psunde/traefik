package tcp

import (
	"crypto/tls"
	"net"

	"github.com/containous/traefik/v2/pkg/log"
	"github.com/containous/traefik/v2/pkg/tcp/starttls"
)

var supportedSTARTTLSProtocols = []string{"xmpp"}

// Determines if the STARTTLS protocol is supported
func IsSTARTTLSProtocolSupported(protocol string) bool {
	for _, p := range supportedSTARTTLSProtocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// Handler for specific STARTTLS protocol
type STARTTLSProtocolHandler interface {
	// Performs STARTTLS on the specified protocol
	StartTLS(conn net.Conn) error
	// Returns custom SNI to find correct certifcate
	ServerName() string
}

// STARTTLSHandler handles STARTTLS connections
type STARTTLSHandler struct {
	Next     Handler
	Config   *tls.Config
	Protocol string
}

// ServeTCP terminates the STARTTLS connection
func (s *STARTTLSHandler) ServeTCP(conn WriteCloser) {
	var protoHandler STARTTLSProtocolHandler
	switch s.Protocol {
	case "xmpp":
		protoHandler = new(starttls.XMPP)
	default:
		// Should not happen, but just to be sure
		return
	}

	if err := protoHandler.StartTLS(conn); err != nil {
		log.Errorf("Could not start tls: %s", err.Error())
		return
	}

	f := s.Config.GetCertificate
	s.Config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if sni := protoHandler.ServerName(); sni != "" {
			clientHello.ServerName = sni
		}

		return f(clientHello)
	}

	s.Next.ServeTCP(tls.Server(conn, s.Config))
}
