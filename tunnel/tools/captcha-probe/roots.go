package main

import (
	"crypto/x509"
	"embed"
	"sync"
)

// Additive trust anchors, same as vkRootCAPool() in libwg-go/vk_certs.go.

//go:embed certs/russian_trusted_root_ca.pem certs/russian_trusted_sub_ca.pem certs/russian_trusted_sub_ca_2024.pem certs/vk_self_signed.cer
var vkExtraRootsFS embed.FS

var vkRootCAPoolState struct {
	sync.Once
	pool *x509.CertPool
}

func vkRootCAPool() *x509.CertPool {
	vkRootCAPoolState.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		entries, _ := vkExtraRootsFS.ReadDir("certs")
		for _, e := range entries {
			pem, err := vkExtraRootsFS.ReadFile("certs/" + e.Name())
			if err != nil {
				continue
			}
			pool.AppendCertsFromPEM(pem)
		}
		vkRootCAPoolState.pool = pool
	})
	return vkRootCAPoolState.pool
}
