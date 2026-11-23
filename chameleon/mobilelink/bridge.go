package mobilelink

import (
	"io"
	"net"
	"sync"
)

func bridge(left, right net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyHalf(left, right)
	go copyHalf(right, left)
	wait.Wait()
	_ = left.Close()
	_ = right.Close()
}
