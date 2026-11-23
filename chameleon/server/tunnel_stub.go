//go:build !linux

package main

import "fmt"

type kernelTunnel struct{}

func (k *kernelTunnel) Name() string { return "" }

func (k *kernelTunnel) WritePacket(_ []byte) error {
	return fmt.Errorf("kernel tunnel is not supported on this platform")
}

func (k *kernelTunnel) ReadPacket(_ []byte) (int, error) {
	return 0, fmt.Errorf("kernel tunnel is not supported on this platform")
}

func (k *kernelTunnel) Close() error { return nil }

func startKernelTunnel(_ string, _ string, _ int, _ bool) (*kernelTunnel, error) {
	return nil, fmt.Errorf("kernel tunnel requires linux")
}
