package agent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"sync"
	"syscall"

	"github.com/spiffe/spire/pkg/agent/attestor"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"path"

	tomb "gopkg.in/tomb.v2"
)

type Agent struct {
	c   *Config
	t   *tomb.Tomb
	mtx *sync.RWMutex

	Catalog   catalog.Catalog
	Attestor  attestor.Attestor
	Manager   manager.Manager
	Endpoints endpoints.Endpoints
}

// Run the agent
// This method initializes the agent, including its plugins,
// and then blocks on the main event loop.
func (a *Agent) Run() error {
	syscall.Umask(a.c.Umask)

	a.t.Go(a.run)
	return a.t.Wait()
}

func (a *Agent) Shutdown() {
	a.t.Kill(nil)
}

func (a *Agent) run() error {
	err := a.startPlugins()
	if err != nil {
		return err
	}

	as, err := a.attest()
	if err != nil {
		return err
	}

	err = a.startManager(as.SVID, as.Key, as.Bundle)
	if err != nil {
		return err
	}
	a.t.Go(func() error { return a.startEndpoints(as.Bundle) })
	a.t.Go(a.superviseManager)

	<-a.t.Dying()
	a.shutdown()
	return nil
}

func (a *Agent) startPlugins() error {
	return a.Catalog.Run()
}

func (a *Agent) attest() (*attestor.AttestationResult, error) {
	config := attestor.Config{
		Catalog:       a.Catalog,
		JoinToken:     a.c.JoinToken,
		TrustDomain:   a.c.TrustDomain,
		TrustBundle:   a.c.TrustBundle,
		DataDir:       a.c.DataDir,
		Log:           a.c.Log.WithField("subsystem_name", "attestor"),
		ServerAddress: a.c.ServerAddress,
	}
	a.Attestor = attestor.New(&config)
	return a.Attestor.Attest()
}

func (a *Agent) superviseManager() error {
	// Wait until the manager stopped working.
	<-a.Manager.Stopped()
	err := a.Manager.Err()
	a.mtx.Lock()
	a.Manager = nil
	a.mtx.Unlock()
	return err
}

func (a *Agent) shutdown() {
	if a.Endpoints != nil {
		a.Endpoints.Shutdown()
	}

	if a.Manager != nil {
		a.Manager.Shutdown()
	}

	if a.Catalog != nil {
		a.Catalog.Stop()
	}
}

func (a *Agent) startManager(svid *x509.Certificate, key *ecdsa.PrivateKey, bundle []*x509.Certificate) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.Manager != nil {
		return errors.New("cannot start cache manager, there is a manager instantiated already")
	}

	mgrConfig := &manager.Config{
		SVID:            svid,
		SVIDKey:         key,
		Bundle:          bundle,
		TrustDomain:     a.c.TrustDomain,
		ServerAddr:      a.c.ServerAddress,
		Log:             a.c.Log,
		BundleCachePath: path.Join(a.c.DataDir, "bundle.der"),
		SVIDCachePath:   path.Join(a.c.DataDir, "agent_svid.der"),
	}

	mgr, err := manager.New(mgrConfig)
	if err != nil {
		return err
	}
	a.Manager = mgr
	return a.Manager.Start()
}

// TODO: Shouldn't need to pass bundle here
func (a *Agent) startEndpoints(bundle []*x509.Certificate) error {
	config := &endpoints.Config{
		Bundle:   bundle,
		BindAddr: a.c.BindAddress,
		Catalog:  a.Catalog,
		Manager:  a.Manager,
		Log:      a.c.Log.WithField("subsystem_name", "endpoints"),
	}

	e := endpoints.New(config)
	err := e.Start()
	if err != nil {
		return err
	}

	a.mtx.Lock()
	a.Endpoints = e
	a.mtx.Unlock()
	return a.Endpoints.Wait()
}
