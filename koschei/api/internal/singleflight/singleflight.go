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
	c, duplicate := g.acquire(key)
	if duplicate {
		<-c.done
		return c.val, c.err, true
	}

	c.val, c.err = fn()
	g.complete(key, c)
	return c.val, c.err, false
}

// DoContext is the context-aware form of Do. A duplicate caller may stop
// waiting when its own context is canceled without canceling the in-flight
// leader. The leader's work remains governed by the context captured by fn.
func (g *Group) DoContext(ctx context.Context, key string, fn func() (interface{}, error)) (interface{}, error, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err, false
	}

	c, duplicate := g.acquire(key)
	if duplicate {
		select {
		case <-c.done:
			return c.val, c.err, true
		case <-ctx.Done():
			return nil, ctx.Err(), true
		}
	}

	c.val, c.err = fn()
	g.complete(key, c)
	return c.val, c.err, false
}

func (g *Group) acquire(key string) (*call, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		return c, true
	}
	c := &call{done: make(chan struct{})}
	g.m[key] = c
	return c, false
}

func (g *Group) complete(key string, c *call) {
	close(c.done)
	g.mu.Lock()
	if current, ok := g.m[key]; ok && current == c {
		delete(g.m, key)
	}
	g.mu.Unlock()
}
