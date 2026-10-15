package main

import (
	"net"
	"sync"
)

// meterConnectionLimit bounds the TCP/TLS work that an internet-facing meter
// ingress accepts at once. A valid meter event is tiny and short lived, so a
// small bound comfortably exceeds the GPU CVM's expected parallelism while
// preventing incomplete TLS handshakes from allocating unbounded goroutines.
const meterConnectionLimit = 64

type limitedListener struct {
	net.Listener
	slots  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newLimitedListener(listener net.Listener, maximum int) net.Listener {
	if maximum < 1 {
		panic("limited listener maximum must be positive")
	}
	return &limitedListener{
		Listener: listener,
		slots:    make(chan struct{}, maximum),
		closed:   make(chan struct{}),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConnection{
		Conn:    connection,
		release: func() { <-l.slots },
	}, nil
}

func (l *limitedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
