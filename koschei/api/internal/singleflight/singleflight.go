// Package singleflight provides duplicate function call suppression.
package singleflight

import (
	"context"
	"sync"
)

type call struct {
	done chan struct{}
	val  interface{}
	err  error
}

// Group represents a class of work and forms a namespace in which units of
// work can be executed with duplicate suppression.
type Group struct {
	mu sync.Mutex
	m  map[string]*call
}

// Do executes and returns the results of the given function, making sure that
// only one execution is in-flight for a given key at a time. If a duplicate
// comes in, the duplicate caller waits for the original to complete and
// receives the same results.
func (g *Group) Do(key string, fn func() (interface{}, error)) (interface{}, error, bool) {
	return g.do(context.Background(), key, fn, false)
}

// DoContext is Do with cancellation for duplicate waiters. The caller that
// starts the work still owns fn and should pass its context into fn when it
// needs cancellation. A later duplicate can stop waiting without cancelling
// the shared in-flight work required by the original caller.
func (g *Group) DoContext(ctx context.Context, key string, fn func() (interface{}, error)) (interface{}, error, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	return g.do(ctx, key, fn, true)
}

func (g *Group) do(ctx context.Context, key string, fn func() (interface{}, error), cancellableWait bool) (interface{}, error, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		if cancellableWait {
			select {
			case <-c.done:
				return c.val, c.err, true
			case <-ctx.Done():
				return nil, ctx.Err(), true
			}
		}
		<-c.done
		return c.val, c.err, true
	}
	c := &call{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	close(c.done)

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err, false
}
