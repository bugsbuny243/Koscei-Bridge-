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
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.val, c.err, true
	}
	c := &call{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	g.finish(key, c)
	return c.val, c.err, false
}

// DoContext executes one shared unit of work asynchronously and lets every
// caller, including the leader, stop waiting when its own context is done.
// Cancellation of a waiter does not cancel the shared work; fn must manage the
// lifetime of the shared operation itself.
func (g *Group) DoContext(ctx context.Context, key string, fn func() (interface{}, error)) (interface{}, error, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err, false
	}

	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	c, shared := g.m[key]
	if !shared {
		c = &call{done: make(chan struct{})}
		g.m[key] = c
		go func() {
			c.val, c.err = fn()
			g.finish(key, c)
		}()
	}
	g.mu.Unlock()

	select {
	case <-c.done:
		return c.val, c.err, shared
	case <-ctx.Done():
		return nil, ctx.Err(), shared
	}
}

func (g *Group) finish(key string, c *call) {
	g.mu.Lock()
	if current, ok := g.m[key]; ok && current == c {
		delete(g.m, key)
	}
	g.mu.Unlock()
	close(c.done)
}
