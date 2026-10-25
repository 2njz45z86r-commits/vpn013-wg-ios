// SPDX-License-Identifier: MIT
package r013gate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const maxUAPIBytes = 8 * 1024 * 1024
const maxUAPIConnections = 4

type PrimaryUAPIDevice interface {
	IpcGetOperation(io.Writer) error
	IpcSet(string) error
}

// PrimaryUAPIServer preserves ordinary get/set framing while bounding local
// pipe workers and messages. A complete set body is read BEFORE entering the
// device's primary mutation fence, so a stalled writer cannot own that fence.
// Get stays read-only. Only the existing protected pipe listener may call Serve.
type PrimaryUAPIServer struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	stopParent func() bool
	device     PrimaryUAPIDevice
	closed     bool
	live       map[net.Conn]struct{}
	active     sync.WaitGroup
	drainOnce  sync.Once
	drained    chan struct{}
}

func NewPrimaryUAPIServer(parent context.Context, device PrimaryUAPIDevice) (*PrimaryUAPIServer, error) {
	if parent == nil || parent.Err() != nil || device == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	s := &PrimaryUAPIServer{ctx: ctx, cancel: cancel, device: device, live: make(map[net.Conn]struct{}), drained: make(chan struct{})}
	s.stopParent = context.AfterFunc(parent, s.Invalidate)
	return s, nil
}
func (s *PrimaryUAPIServer) Serve(connection net.Conn) bool {
	if connection == nil {
		return false
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || len(s.live) >= maxUAPIConnections {
		s.mu.Unlock()
		connection.Close()
		return false
	}
	s.live[connection] = struct{}{}
	s.active.Add(1)
	s.mu.Unlock()
	go s.handle(connection)
	return true
}
func (s *PrimaryUAPIServer) Invalidate() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	live := make([]net.Conn, 0, len(s.live))
	for c := range s.live {
		live = append(live, c)
	}
	s.mu.Unlock()
	for _, c := range live {
		c.Close()
	}
}
func (s *PrimaryUAPIServer) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	s.Invalidate()
	s.stopParent()
	s.drainOnce.Do(func() { go func() { s.active.Wait(); close(s.drained) }() })
	select {
	case <-s.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func boundedUAPILine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if len(line) >= limit {
			return "", io.ErrShortBuffer
		}
		line = append(line, b)
		if b == '\n' {
			return string(line), nil
		}
	}
}

type cappedUAPIWriter struct {
	writer    io.Writer
	remaining int
}

func (w *cappedUAPIWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, io.ErrShortBuffer
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	return n, err
}
func (s *PrimaryUAPIServer) handle(connection net.Conn) {
	defer func() { connection.Close(); s.mu.Lock(); delete(s.live, connection); s.mu.Unlock(); s.active.Done() }()
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	for s.ctx.Err() == nil {
		connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		operation, err := boundedUAPILine(reader, 16)
		if err != nil {
			return
		}
		var result error
		switch operation {
		case "get=1\n":
			end, err := boundedUAPILine(reader, 2)
			if err != nil || end != "\n" {
				return
			}
			if s.ctx.Err() != nil {
				return
			}
			connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
			limited := &cappedUAPIWriter{writer: writer, remaining: maxUAPIBytes}
			result = s.device.IpcGetOperation(limited)
		case "set=1\n":
			var body strings.Builder
			for {
				line, err := boundedUAPILine(reader, maxUAPIBytes-body.Len())
				if err != nil {
					return
				}
				if line == "\n" {
					break
				}
				body.WriteString(line)
			}
			if s.ctx.Err() != nil {
				return
			}
			result = s.device.IpcSet(body.String())
			connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
		default:
			return
		}
		code := int64(0)
		if result != nil {
			code = -55
			var coded interface{ ErrorCode() int64 }
			if errors.As(result, &coded) {
				code = coded.ErrorCode()
			}
		}
		if _, err = fmt.Fprintf(writer, "errno=%d\n\n", code); err != nil {
			return
		}
		if writer.Flush() != nil {
			return
		}
	}
}
