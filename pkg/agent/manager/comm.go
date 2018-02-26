package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"sync"

	spiffe_tls "github.com/spiffe/go-spiffe/tls"
	"github.com/spiffe/spire/proto/api/node"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type client struct {
	conn   *grpc.ClientConn
	stream node.Node_FetchSVIDClient
}

type clientsPool struct {
	// Map of client connections to the server keyed by SPIFFEID.
	clients map[string]*client
	// Protects access to the pool.
	m *sync.Mutex
}

func (m *manager) newGRPCConn(svid *x509.Certificate, key *ecdsa.PrivateKey) (*grpc.ClientConn, error) {
	var tlsCert []tls.Certificate
	var tlsConfig *tls.Config

	spiffePeer := &spiffe_tls.TLSPeer{
		SpiffeIDs:  []string{m.serverSPIFFEID},
		TrustRoots: m.bundleAsCertPool(),
	}
	tlsCert = append(tlsCert, tls.Certificate{Certificate: [][]byte{svid.Raw}, PrivateKey: key})
	tlsConfig = spiffePeer.NewTLSConfig(tlsCert)
	dialCreds := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))

	conn, err := grpc.Dial(m.serverAddr.String(), dialCreds)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// newClient adds a new client to the pool and associates it to the specified list of spiffeIDs.
func (m *manager) newClient(spiffeIDs []string, svid *x509.Certificate, key *ecdsa.PrivateKey) error {
	// If there is no pool yet, create one.
	m.mtx.Lock()
	if m.clients == nil {
		m.clients = &clientsPool{clients: map[string]*client{}, m: &sync.Mutex{}}
	}
	m.mtx.Unlock()

	conn, err := m.newGRPCConn(svid, key)
	if err != nil {
		return err
	}

	for _, id := range spiffeIDs {
		err = m.clients.add(id, conn)
		if err != nil {
			conn.Close()
			return err
		}
	}

	return nil
}

func (p *clientsPool) add(spiffeID string, conn *grpc.ClientConn) error {
	// If there is already a connection with the specified spiffeID, close it first.
	if c := p.get(spiffeID); c != nil {
		c.stream.CloseSend()
		c.conn.Close()
	}

	nodeClient := node.NewNodeClient(conn)

	stream, err := nodeClient.FetchSVID(context.TODO())
	if err != nil {
		return err
	}

	p.m.Lock()
	defer p.m.Unlock()
	p.clients[spiffeID] = &client{conn: conn, stream: stream}
	return nil
}

func (p *clientsPool) get(spiffeID string) *client {
	p.m.Lock()
	defer p.m.Unlock()
	return p.clients[spiffeID]
}

// close releases the pool's resources.
func (p *clientsPool) close() {
	p.m.Lock()
	defer p.m.Unlock()
	for _, c := range p.clients {
		c.close()
	}
}

func (c *client) close() {
	c.stream.CloseSend()
	c.conn.Close()
}
