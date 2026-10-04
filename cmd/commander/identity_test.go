package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
)

func newVerifiedAgentCertificate(t *testing.T, agentName string, serial int64) (*tls.ConnectionState, *x509.Certificate) {
	t.Helper()
	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serial + 1000),
		Subject:               pkix.Name{CommonName: "Sentinel Test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURI, err := url.Parse("spiffe://sentinel.test/" + agentName)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: agentName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{agentName},
		URIs:                  []*url.URL{identityURI},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, root, &clientKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifiedChains, err := clientCert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatal(err)
	}

	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
		VerifiedChains:   verifiedChains,
	}, clientCert
}

func identityBindingsFor(t *testing.T, agentName string, cert *x509.Certificate) agentIdentityBindings {
	t.Helper()
	bindings, err := parseAgentIdentityBindings(agentName + "=" + certificateFingerprint(cert))
	if err != nil {
		t.Fatal(err)
	}
	return bindings
}

func resetAgentConnections(t *testing.T) {
	t.Helper()
	clientsMu.Lock()
	previous := clients
	clients = make(map[string]*AgentConnection)
	clientsMu.Unlock()
	t.Cleanup(func() {
		clientsMu.Lock()
		clients = previous
		clientsMu.Unlock()
	})
}

func newWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverConnection := make(chan *websocket.Conn, 1)
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConnection <- conn
		<-serverDone
		_ = conn.Close()
	}))

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial test WebSocket: %v", err)
	}
	var peer *websocket.Conn
	select {
	case peer = <-serverConnection:
	case <-time.After(time.Second):
		close(serverDone)
		_ = client.Close()
		server.Close()
		t.Fatal("test WebSocket server did not upgrade the connection")
	}
	t.Cleanup(func() {
		close(serverDone)
		_ = peer.Close()
		_ = client.Close()
		server.Close()
	})
	return peer, client
}

func TestCertificateFingerprintIsCanonicalSHA256(t *testing.T) {
	_, cert := newVerifiedAgentCertificate(t, "scout-1", 1)
	want := sha256.Sum256(cert.Raw)
	fingerprint := certificateFingerprint(cert)
	if fingerprint != hex.EncodeToString(want[:]) {
		t.Fatalf("fingerprint = %q, want SHA-256 %q", fingerprint, hex.EncodeToString(want[:]))
	}
	if len(fingerprint) != 64 || fingerprint != strings.ToLower(fingerprint) || strings.Contains(fingerprint, ":") {
		t.Fatalf("fingerprint is not canonical lowercase hexadecimal: %q", fingerprint)
	}
	if certificateFingerprint(cert) != fingerprint {
		t.Fatal("fingerprint changed for the same certificate")
	}
	if certificateFingerprint(nil) != "" {
		t.Fatal("nil certificate produced a fingerprint")
	}
}

func TestParseAgentIdentityBindings(t *testing.T) {
	bindings, err := parseAgentIdentityBindings("scout-1=" + strings.Repeat("A", 64) + ", scout-2=" + strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("parse valid bindings: %v", err)
	}
	if !bindings.authorizes("scout-1", strings.Repeat("a", 64)) || !bindings.authorizes("scout-2", strings.Repeat("b", 64)) {
		t.Fatal("valid bindings were not canonicalized and retained")
	}

	for _, raw := range []string{
		"",
		"scout-1=short",
		"scout-1=" + strings.Repeat("g", 64),
		"bad/name=" + strings.Repeat("a", 64),
		"scout-1=" + strings.Repeat("a", 64) + ",scout-1=" + strings.Repeat("b", 64),
		"scout-1=" + strings.Repeat("a", 64) + ",scout-2=" + strings.Repeat("a", 64),
		"scout-1=" + strings.Repeat("a", 64) + ",",
	} {
		if _, err := parseAgentIdentityBindings(raw); err == nil {
			t.Errorf("invalid identity bindings accepted: %q", raw)
		}
	}
}

func TestCertificateSANMatchesAgent(t *testing.T) {
	validURISAN, err := url.Parse("spiffe://sentinel.test/scout-1")
	if err != nil {
		t.Fatal(err)
	}
	validCertificates := []*x509.Certificate{
		{DNSNames: []string{"scout-1"}},
		{DNSNames: []string{"scout-1.sentinel.test"}},
		{URIs: []*url.URL{validURISAN}},
	}
	for _, cert := range validCertificates {
		if !certificateSANMatchesAgent(cert, "scout-1") {
			t.Errorf("valid certificate SAN rejected: %+v", cert)
		}
	}

	invalidURISAN, err := url.Parse("spiffe://sentinel.test/scout-2")
	if err != nil {
		t.Fatal(err)
	}
	invalidCertificates := []*x509.Certificate{
		{DNSNames: []string{"scout-2"}},
		{URIs: []*url.URL{invalidURISAN}},
		{},
	}
	for _, cert := range invalidCertificates {
		if certificateSANMatchesAgent(cert, "scout-1") {
			t.Errorf("mismatched or missing certificate SAN accepted: %+v", cert)
		}
	}
}

func TestAuthorizeAgentIdentity(t *testing.T) {
	stateA, certA := newVerifiedAgentCertificate(t, "scout-1", 2)
	stateBForScout1, _ := newVerifiedAgentCertificate(t, "scout-1", 3)
	stateBForScout2, _ := newVerifiedAgentCertificate(t, "scout-2", 4)
	stateMismatchedSAN, certMismatchedSAN := newVerifiedAgentCertificate(t, "scout-2", 6)
	bindings := identityBindingsFor(t, "scout-1", certA)
	bindingsWithMismatchedSAN := identityBindingsFor(t, "scout-1", certMismatchedSAN)
	fingerprint, rejection := authorizeAgentIdentity(stateA, "scout-1", bindings)
	if rejection != "" || fingerprint != certificateFingerprint(certA) {
		t.Fatalf("valid certificate rejected: fingerprint=%q rejection=%q", fingerprint, rejection)
	}
	connection, derivedFingerprint, rejection := authenticatedAgentConnection(stateA, "scout-1", nil, bindings)
	if rejection != "" || connection == nil || derivedFingerprint != fingerprint || connection.CertificateFingerprint != fingerprint {
		t.Fatalf("registration did not derive identity from the TLS certificate: connection=%v fingerprint=%q rejection=%q", connection, derivedFingerprint, rejection)
	}

	tests := []struct {
		name       string
		state      *tls.ConnectionState
		agentName  string
		bindings   agentIdentityBindings
		wantReason agentIdentityRejection
	}{
		{name: "missing certificate", state: nil, agentName: "scout-1", bindings: bindings, wantReason: identityMissingPeerCertificate},
		{name: "unverified certificate", state: &tls.ConnectionState{PeerCertificates: stateA.PeerCertificates}, agentName: "scout-1", bindings: bindings, wantReason: identityUnverifiedPeerCertificate},
		{name: "unknown certificate", state: stateBForScout1, agentName: "scout-1", bindings: bindings, wantReason: identityAgentBoundToOtherCertificate},
		{name: "certificate used for another agent", state: stateA, agentName: "scout-2", bindings: bindings, wantReason: identityCertificateBoundToOtherAgent},
		{name: "agent name bound to another certificate", state: stateBForScout1, agentName: "scout-1", bindings: identityBindingsFor(t, "scout-1", certA), wantReason: identityAgentBoundToOtherCertificate},
		{name: "unknown agent", state: stateBForScout2, agentName: "scout-2", bindings: bindings, wantReason: identityUnauthorizedCertificate},
		{name: "certificate SAN mismatch", state: stateMismatchedSAN, agentName: "scout-1", bindings: bindingsWithMismatchedSAN, wantReason: identityCertificateNameMismatch},
		{name: "invalid agent name", state: stateA, agentName: "scout/1", bindings: bindings, wantReason: identityInvalidAgentName},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, got := authorizeAgentIdentity(test.state, test.agentName, test.bindings); got != test.wantReason {
				t.Fatalf("rejection = %q, want %q", got, test.wantReason)
			}
		})
	}
}

func TestRegisterAgentConnectionReplacesOnlySameIdentity(t *testing.T) {
	resetAgentConnections(t)
	oldServerConn, oldClientConn := newWebSocketPair(t)
	newServerConn, _ := newWebSocketPair(t)
	state, cert := newVerifiedAgentCertificate(t, "scout-1", 5)
	fingerprint := certificateFingerprint(cert)
	bindings := identityBindingsFor(t, "scout-1", cert)
	if _, rejection := authorizeAgentIdentity(state, "scout-1", bindings); rejection != "" {
		t.Fatalf("test certificate was not authorized: %q", rejection)
	}

	first, derivedFingerprint, rejection := authenticatedAgentConnection(state, "scout-1", oldServerConn, bindings)
	if rejection != "" || derivedFingerprint != fingerprint {
		t.Fatalf("valid registration certificate was rejected: fingerprint=%q rejection=%q", derivedFingerprint, rejection)
	}
	if old, rejection := registerAgentConnection(first, bindings); rejection != "" || old != nil {
		t.Fatalf("initial registration failed: old=%v rejection=%q", old, rejection)
	}
	second, _, rejection := authenticatedAgentConnection(state, "scout-1", newServerConn, bindings)
	if rejection != "" {
		t.Fatalf("same-identity reconnect authorization failed: %q", rejection)
	}
	old, rejection := registerAgentConnection(second, bindings)
	if rejection != "" || old != first {
		t.Fatalf("same-identity reconnect failed: old=%p want=%p rejection=%q", old, first, rejection)
	}
	closeReplacedAgentConnection(old)
	_ = oldClientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, closeErr := oldClientConn.ReadMessage()
	var websocketCloseErr *websocket.CloseError
	if !errors.As(closeErr, &websocketCloseErr) || websocketCloseErr.Code != websocket.CloseNormalClosure {
		t.Fatalf("replaced Scout connection close = %v, want normal WebSocket close", closeErr)
	}
	if clients["scout-1"] != second {
		t.Fatal("reconnect did not replace the active connection")
	}
	if currentAuthorizedAgentConnection("scout-1", first, bindings) {
		t.Fatal("replaced connection remains active")
	}
	if agentConnectionForTask("scout-1", bindings) != second {
		t.Fatal("task routing did not select the current authorized connection")
	}

	unauthorized := &AgentConnection{Name: "scout-1", CertificateFingerprint: strings.Repeat("b", 64), Conn: &websocket.Conn{}}
	if _, rejection := registerAgentConnection(unauthorized, bindings); rejection == "" {
		t.Fatal("different certificate was allowed to replace the agent connection")
	}
	if clients["scout-1"] != second {
		t.Fatal("rejected certificate changed the active agent map")
	}
	otherName := &AgentConnection{Name: "scout-2", CertificateFingerprint: fingerprint, Conn: &websocket.Conn{}}
	if _, rejection := registerAgentConnection(otherName, bindings); rejection == "" {
		t.Fatal("certificate was allowed to register under another agent name")
	}
	if _, exists := clients["scout-2"]; exists {
		t.Fatal("rejected identity remained in the active agent map")
	}
}

func TestAgentConnectionTaskRoutingAndReportIdentity(t *testing.T) {
	resetAgentConnections(t)
	fingerprintA := strings.Repeat("a", 64)
	fingerprintB := strings.Repeat("b", 64)
	bindings, err := parseAgentIdentityBindings("scout-1=" + fingerprintA + ",scout-2=" + fingerprintB)
	if err != nil {
		t.Fatal(err)
	}
	connectionA := &AgentConnection{Name: "scout-1", CertificateFingerprint: fingerprintA, Conn: &websocket.Conn{}}
	connectionB := &AgentConnection{Name: "scout-2", CertificateFingerprint: fingerprintB, Conn: &websocket.Conn{}}
	clientsMu.Lock()
	clients["scout-1"] = connectionA
	clients["scout-2"] = connectionB
	clientsMu.Unlock()

	if got := agentConnectionForTask("scout-1", bindings); got != connectionA || got == connectionB {
		t.Fatal("task for scout-1 was not routed exclusively to scout-1's authorized connection")
	}
	if got := agentConnectionForTask("scout-2", bindings); got != connectionB {
		t.Fatal("task for scout-2 was not routed to scout-2's authorized connection")
	}

	message := models.Command{Type: "REPORT", Agent: "scout-1", Status: 200, Time: "45ms", CPU: 10, RAM: 20, Disk: 30}
	if !validAgentReportIdentity(message, connectionA, bindings) {
		t.Fatal("valid report identity was rejected")
	}
	message.Agent = "scout-2"
	if validAgentReportIdentity(message, connectionA, bindings) {
		t.Fatal("report with a mismatched logical agent was accepted")
	}
	message.Agent = "scout-1"
	unauthorizedConnection := &AgentConnection{Name: "scout-1", CertificateFingerprint: fingerprintB, Conn: &websocket.Conn{}}
	if validAgentReportIdentity(message, unauthorizedConnection, bindings) {
		t.Fatal("report from an unauthorized certificate identity was accepted")
	}

	clientsMu.Lock()
	clients["scout-1"] = unauthorizedConnection
	clientsMu.Unlock()
	if agentConnectionForTask("scout-1", bindings) != nil {
		t.Fatal("unauthorized connection received task routing")
	}
}
