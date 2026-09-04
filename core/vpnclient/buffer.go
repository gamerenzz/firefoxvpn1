package vpnclient

import (
	"io"
	"sync"
)

const DefaultBufferSize = 1 << 20 // 1MB 环形缓冲区

type TunnelWriteBuffer struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	buf      []byte
	n        int
	off      int
	closed   bool
	readErr  error
}

func NewTunnelWriteBuffer(size int) *TunnelWriteBuffer {
	if size < 1 {
		size = DefaultBufferSize
	}
	b := &TunnelWriteBuffer{buf: make([]byte, size)}
	b.notEmpty = sync.NewCond(&b.mu)
	b.notFull = sync.NewCond(&b.mu)
	return b
}

func (b *TunnelWriteBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.n == 0 && b.readErr == nil && !b.closed {
		b.notEmpty.Wait()
	}
	if b.n == 0 {
		if b.readErr != nil {
			return 0, b.readErr
		}
		return 0, io.EOF
	}

	end := b.off + b.n
	if end > len(b.buf) {
		end = len(b.buf)
	}
	n := copy(p, b.buf[b.off:end])
	b.off = (b.off + n) % len(b.buf)
	b.n -= n
	b.notFull.Broadcast()
	return n, nil
}

func (b *TunnelWriteBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := 0
	for len(p) > 0 {
		for b.n == len(b.buf) && b.readErr == nil && !b.closed {
			b.notFull.Wait()
		}
		if b.readErr != nil {
			return total, b.readErr
		}
		if b.closed {
			return total, io.ErrClosedPipe
		}

		space := len(b.buf) - b.n
		head := (b.off + b.n) % len(b.buf)
		writable := len(b.buf) - head
		if space < writable {
			writable = space
		}
		if writable > len(p) {
			writable = len(p)
		}
		copy(b.buf[head:], p[:writable])
		b.n += writable
		p = p[writable:]
		total += writable
		b.notEmpty.Broadcast()
	}
	return total, nil
}

func (b *TunnelWriteBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()
	return nil
}

func (b *TunnelWriteBuffer) FailRead(err error) {
	b.mu.Lock()
	if b.readErr == nil {
		b.readErr = err
	}
	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()
	b.mu.Unlock()
}
