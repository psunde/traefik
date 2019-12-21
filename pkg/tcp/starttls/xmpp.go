package starttls

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"time"
)

// Handler for STARTTLS on XMPP (https://tools.ietf.org/html/rfc6120#section-5)
type XMPP struct {
	conn net.Conn
	dec  *xml.Decoder

	state struct {
		from     string
		streamId int64
	}
}

func (x *XMPP) StartTLS(conn net.Conn) error {
	x.conn = conn
	x.dec = xml.NewDecoder(conn)

	var element xml.StartElement
	if e, err := x.nextElement(); err != nil {
		return err
	} else if e.Name.Space != "stream" || e.Name.Local != "stream" {
		x.sendErrorNotWellFormed()
		return errors.New("client sent invalid initial stream header")
	} else {
		element = e
	}

	for _, a := range element.Attr {
		if a.Name.Local == "to" {
			x.state.from = a.Value
			break
		}
	}
	if x.state.from == "" {
		x.sendErrorImproperAddressing()
		return errors.New("client did not sent 'to' attribute in initial stream header")
	}

	if err := x.sendFeatureList(); err != nil {
		return err
	}

	if e, err := x.nextElement(); err != nil {
		return err
	} else if e.Name.Local != "starttls" {
		x.sendErrorPolicyViolation()
		return fmt.Errorf("client requested invalid feature '%s'", e.Name.Local)
	}

	return x.sendProceed()
}

func (x *XMPP) ServerName() string {
	return x.state.from
}

func (x *XMPP) startStream() error {
	if x.state.streamId != 0 {
		return errors.New("stream already started")
	}

	id := time.Now().UnixNano()
	var from string
	if x.state.from != "" {
		from = fmt.Sprintf("from='%s' ", x.state.from)
	}
	_, err := fmt.Fprintf(x.conn, `<stream:stream id='%d' version='1.0' xml:lang='en' xmlns:stream='http://etherx.jabber.org/streams' %sxmlns='jabber:client'>`, id, from)
	if err != nil {
		return err
	}

	x.state.streamId = id
	return nil
}

func (x *XMPP) closeStream() error {
	if x.state.streamId == 0 {
		return errors.New("stream not started")
	}

	_, err := x.conn.Write([]byte(`</stream:stream>`))
	if err != nil {
		return err
	}

	x.state.streamId = 0
	return nil
}

func (x *XMPP) sendFeatureList() error {
	return x.send(`<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>`)
}

func (x *XMPP) sendProceed() error {
	return x.send(`<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`)
}

func (x *XMPP) sendErrorNotWellFormed() error {
	return x.sendError(`<not-well-formed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>`)
}

func (x *XMPP) sendErrorImproperAddressing() error {
	return x.sendError(`<improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Missing &apos;to&apos; attribute</text>`)
}

func (x *XMPP) sendErrorPolicyViolation() error {
	return x.sendError(`<policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Use of STARTTLS required</text>`)
}

func (x *XMPP) sendError(er string) error {
	err := x.send(fmt.Sprintf(`<stream:error>%s</stream:error>`, er))
	if err != nil {
		return err
	}
	return x.closeStream()
}

func (x *XMPP) send(data string) (err error) {
	if x.state.streamId == 0 {
		if err := x.startStream(); err != nil {
			return err
		}
	}

	_, err = x.conn.Write([]byte(data))
	return
}

func (x *XMPP) nextElement() (element xml.StartElement, err error) {
	for {
		var t xml.Token
		t, err = x.dec.RawToken()
		if err != nil {
			x.sendErrorNotWellFormed()
			return
		}
		if _, ok := t.(xml.StartElement); !ok {
			continue
		}
		return t.(xml.StartElement), nil
	}
}
