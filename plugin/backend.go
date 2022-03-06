package quay

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type quayBackend struct {
	*framework.Backend
	sync.RWMutex
	client *client

	roleLocks []*locksutil.LockEntry
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
			pathRotateRole(b),
		),
		Invalidate: b.invalidate,
	}

	b.roleLocks = locksutil.CreateLocks()

	return b

}

func (b *quayBackend) reset() {
	b.Lock()
	defer b.Unlock()
	b.client = nil
}

func (b *quayBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

func (b *quayBackend) getClient(ctx context.Context, s logical.Storage) (*client, error) {
	b.RLock()
	unlockFunc := b.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.RUnlock()
	b.Lock()
	unlockFunc = b.Unlock

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
The Quay secrets backend.
`
