package main

import (
	"net"
	"testing"
	"time"
)

func TestLimitedListenerBlocksAcceptUntilAnOpenConnectionCloses(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newLimitedListener(base, 1)
	t.Cleanup(func() { _ = listener.Close() })

	clientOne, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientOne.Close()
	serverOne, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			_ = connection.Close()
		}
		accepted <- err
	}()
	clientTwo, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientTwo.Close()

	select {
	case err := <-accepted:
		t.Fatalf("second connection bypassed the limit: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := serverOne.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second connection was not accepted after capacity was released")
	}
}

func TestLimitedListenerCloseUnblocksCapacityWait(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := newLimitedListener(base, 1)

	client, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	returned := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		returned <- err
	}()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-returned:
		if err != net.ErrClosed {
			t.Fatalf("Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock an Accept waiting for capacity")
	}
}
