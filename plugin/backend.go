package quay

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type quayBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *client
}

var _ logical.Factory = Factory

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func backend() *quayBackend {

	b := &quayBackend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{
				framework.WALPrefix,
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Secrets: []*framework.Secret{
			secretRobot(b),
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
			},
			pathRole(b),
			pathCredentials(b),
		),
		Invalidate: b.invalidate,
	}

	return b

}

func (b *quayBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

func (b *quayBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *quayBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(quayConfig)
	}

	newClient, err := newClient(config)
	if err != nil {
		return nil, err
	}

	b.client = newClient

	return b.client, nil
}

const backendHelp = `
The Quay secrets backend..
`
