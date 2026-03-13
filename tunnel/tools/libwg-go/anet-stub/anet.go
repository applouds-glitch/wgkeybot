package anet

import (
	"net"
)

type Dialer struct {
	net.Dialer
}

func NewDialer(d net.Dialer) *Dialer {
	return &Dialer{Dialer: d}
}

type ListenConfig struct {
	net.ListenConfig
}

func NewListenConfig(lc net.ListenConfig) *ListenConfig {
	return &ListenConfig{ListenConfig: lc}
}
