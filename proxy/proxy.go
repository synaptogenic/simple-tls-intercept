package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
)

type Proxy struct{}

func (p *Proxy) Start(certs []tls.Certificate) error {
	println("starting with the following certs")
	for _, c := range certs {
		fmt.Printf("  cert: %v\n", c.Leaf.Subject)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:443", &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Print("Intercept relay started on port 443...")

	// TODO: handle sigint
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Print("somehow you got a non-tls connection buddy")
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("tls handshake error: %v", err)
		return
	}

	serverName := tlsConn.ConnectionState().ServerName
	if serverName == "" {
		log.Printf("SNI is required for interception")
		return
	}

	ips, err := resolveHostnameDirectly(serverName)
	if err != nil || len(ips) == 0 {
		log.Printf("error with resolving upstream: %v, ips: %v", err, ips)
		return
	}

	upstreamConn, err := tls.Dial("tcp", ips[0]+":443", &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
	})
	if err != nil {
		log.Printf("error dialing upstream: %v", err)
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(upstreamConn, io.TeeReader(conn, os.Stdout))
	}()
	io.Copy(conn, io.TeeReader(upstreamConn, os.Stdout))
	<-done
}

func resolveHostnameDirectly(hostname string) ([]string, error) {
	const dnsServer = "8.8.8.8:53" // Google's public DNS server

	// Create a new DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA) // Query for A records
	msg.RecursionDesired = true

	// Use a DNS client to send the query
	client := new(dns.Client)
	response, _, err := client.Exchange(msg, dnsServer)
	if err != nil {
		return nil, err
	}

	// Parse the response
	var ips []string
	for _, answer := range response.Answer {
		if aRecord, ok := answer.(*dns.A); ok {
			ips = append(ips, aRecord.A.String())
		}
	}
	return ips, nil
}
