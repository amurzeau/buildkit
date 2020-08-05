package resolver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	distreference "github.com/docker/distribution/reference"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/source"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var DefaultPool = NewPool()

type Pool struct {
	mu sync.Mutex
	m  map[string]*authHandlerNS
}

func NewPool() *Pool {
	return &Pool{
		m: map[string]*authHandlerNS{},
	}
}

func (p *Pool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m = map[string]*authHandlerNS{}
}

func (p *Pool) GetResolver(hosts docker.RegistryHosts, ref, scope string, sm *session.Manager, g session.Group) *Resolver {
	name := ref
	named, err := distreference.ParseNormalizedNamed(ref)
	if err == nil {
		name = named.Name()
	}

	key := fmt.Sprintf("%s::%s", name, scope)

	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.m[key]
	if !ok {
		h = newAuthHandlerNS()
		p.m[key] = h
	}
	return newResolver(hosts, h, sm, g)
}

func newResolver(hosts docker.RegistryHosts, handler *authHandlerNS, sm *session.Manager, g session.Group) *Resolver {
	if hosts == nil {
		hosts = docker.ConfigureDefaultRegistries(
			docker.WithClient(newDefaultClient()),
			docker.WithPlainHTTP(docker.MatchLocalhost),
		)
	}
	r := &Resolver{
		hosts:   hosts,
		sm:      sm,
		g:       g,
		handler: handler,
	}
	r.Resolver = docker.NewResolver(docker.ResolverOptions{
		Hosts: r.hostsFunc,
	})
	return r
}

type Resolver struct {
	remotes.Resolver
	hosts   docker.RegistryHosts
	sm      *session.Manager
	g       session.Group
	handler *authHandlerNS
	auth    *dockerAuthorizer

	is   images.Store
	mode source.ResolveMode
}

func (r *Resolver) hostsFunc(host string) ([]docker.RegistryHost, error) {
	return func(domain string) ([]docker.RegistryHost, error) {
		v, err := r.handler.g.Do(context.TODO(), domain, func(ctx context.Context) (interface{}, error) {
			// long lock not needed because flightcontrol.Do
			r.handler.mu.Lock()
			v, ok := r.handler.hosts[domain]
			r.handler.mu.Unlock()
			if ok {
				return v, nil
			}
			res, err := r.hosts(domain)
			if err != nil {
				return nil, err
			}
			r.handler.mu.Lock()
			r.handler.hosts[domain] = res
			r.handler.mu.Unlock()
			return res, nil
		})
		if err != nil || v == nil {
			return nil, err
		}
		res := v.([]docker.RegistryHost)
		if len(res) == 0 {
			return nil, nil
		}
		auth := newDockerAuthorizer(res[0].Client, r.handler, r.sm, r.g)
		for i := range res {
			res[i].Authorizer = auth
		}
		return res, nil
	}(host)
}

func (r *Resolver) WithSession(s session.Group) *Resolver {
	r2 := *r
	r2.auth = nil
	r2.g = s
	return &r2
}

func (r *Resolver) WithImageStore(is images.Store, mode source.ResolveMode) *Resolver {
	r2 := *r
	r2.Resolver = r.Resolver
	r2.is = is
	r2.mode = mode
	return &r2
}

func (r *Resolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if atomic.LoadInt64(&r.handler.counter) == 0 {
		r.Resolve(ctx, ref)
	}
	return r.Resolver.Fetcher(ctx, ref)
}

func (r *Resolver) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	if r.mode == source.ResolveModePreferLocal && r.is != nil {
		if img, err := r.is.Get(ctx, ref); err == nil {
			return ref, img.Target, nil
		}
	}

	n, desc, err := r.Resolver.Resolve(ctx, ref)
	if err == nil {
		atomic.AddInt64(&r.handler.counter, 1)
		return n, desc, err
	}

	if r.mode == source.ResolveModeDefault && r.is != nil {
		if img, err := r.is.Get(ctx, ref); err == nil {
			return ref, img.Target, nil
		}
	}

	return "", ocispec.Descriptor{}, err
}
