/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

/*
#include <android/log.h>
extern int wgProtectSocket(int fd);
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

var turnLogger = &AndroidLogger{level: C.ANDROID_LOG_WARN, tag: cstring("WireGuard/TurnClient")}

func turnLog(format string, args ...interface{}) {
	turnLogger.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	err := c.Control(func(fd uintptr) {
		ret := C.wgProtectSocket(C.int(fd))
		if ret != 0 {
			turnLog("[PROTECT] ERROR: wgProtectSocket(fd=%d) returned %d", fd, ret)
		}
	})
	if err != nil {
		turnLog("[PROTECT] ERROR: Control callback failed: %v", err)
	}
	return err
}

var protectedResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: 5 * time.Second,
			Control: protectControl,
		}
		// Skip trying to use the address passed by Go if it's localhost (likely [::1]:53 or 127.0.0.1:53)
		if strings.HasPrefix(address, "127.0.0.1") || strings.HasPrefix(address, "[::1]") {
			turnLog("[DNS] System DNS is localhost (%s), bypassing to Yandex", address)
			return d.DialContext(ctx, "udp", "77.88.8.8:53")
		}

		// Try system DNS (the 'address' passed by Go)
		conn, err := d.DialContext(ctx, network, address)
		if err == nil {
			return conn, nil
		}

		// Fallback to Yandex DNS
		turnLog("[DNS] Lookup to %s failed, trying Yandex DNS (77.88.8.8)", address)
		conn, err = d.DialContext(ctx, "udp", "77.88.8.8:53")
		if err == nil {
			return conn, nil
		}

		// Fallback to Google DNS
		turnLog("[DNS] Yandex lookup failed, trying Google DNS (8.8.8.8)")
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	},
}

// Global HTTP client
var turnHTTPClient *http.Client

func init() {
	// Force Go resolver to ensure protectedResolver.Dial is used
	os.Setenv("GODEBUG", "netdns=go")

	// On Android, Go with CGO_ENABLED=1 uses system DNS resolver via libc
	// This matches the original vk-turn-proxy implementation
	turnHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   protectControl,
				Resolver:  protectedResolver,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func getProtectedClient() *http.Client {
	return turnHTTPClient
}

func getVkCreds(ctx context.Context, link string) (string, string, string, error) {
	doRequest := func(data string, url string, stepName string) (resp map[string]interface{}, err error) {
		client := getProtectedClient()
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("json unmarshal error at %s: %s (body: %s)", stepName, err, string(body))
		}

		if errMsg, ok := resp["error"].(map[string]interface{}); ok {
			return resp, fmt.Errorf("VK API error at %s: %v", stepName, errMsg)
		}

		return resp, nil
	}

	var resp map[string]interface{}
	// Step 1: Get initial anonym token
	data := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	urlStr := "https://login.vk.ru/?act=get_anonym_token"

	resp, err := doRequest(data, urlStr, "1/5 - initial token")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	tokenData, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing data")
	}
	token1 := tokenData["access_token"].(string)

	// Step 2: Get anonymous access token payload
	data = fmt.Sprintf("access_token=%s", token1)
	urlStr = "https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487"

	resp, err = doRequest(data, urlStr, "2/5 - payload")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	responseField, ok := resp["response"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing response field")
	}
	token2 := responseField["payload"].(string)

	// Step 3: Get messages token
	data = fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", url.QueryEscape(token2))
	urlStr = "https://login.vk.ru/?act=get_anonym_token"

	resp, err = doRequest(data, urlStr, "3/5 - messages token")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	tokenData, ok = resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing data field in 3rd step")
	}
	token3 := tokenData["access_token"].(string)

	// Step 4: Get calls token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", url.QueryEscape(link), token3)
	urlStr = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264"

	resp, err = doRequest(data, urlStr, "4/5 - calls token")
	if err != nil {
		return "", "", "", err
	}

	responseField, ok = resp["response"].(map[string]interface{})
	if !ok {
		respJSON, _ := json.Marshal(resp)
		return "", "", "", fmt.Errorf("invalid response from vk: missing response field in 4th step (full resp: %s)", string(respJSON))
	}
	token4 := responseField["token"].(string)

	// Step 5: Get session key from OK
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	urlStr = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, urlStr, "5/5 - session key")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token5 := resp["session_key"].(string)

	// Join conversation and get TURN credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", url.QueryEscape(link), token4, token5)
	urlStr = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, urlStr, "TURN credentials")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	turnServer, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing turn_server")
	}
	user := turnServer["username"].(string)
	pass := turnServer["credential"].(string)
	urls := turnServer["urls"].([]interface{})
	if len(urls) == 0 {
		return "", "", "", fmt.Errorf("invalid response from vk: missing turn urls")
	}
	turnUrl := urls[0].(string)

	clean := strings.Split(turnUrl, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}

	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS client: %w", err)
	}
	return dtlsConn, nil
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, errchan chan<- error) {
	var err error
	defer func() {
		errchan <- err
	}()

	user, pass, turnServerAddr, err1 := getVkCreds(ctx, turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}

	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	ctx1, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if turnParams.udp {
		dialer := &net.Dialer{Control: protectControl, Resolver: protectedResolver}
		rawConn, err2 := dialer.DialContext(ctx1, "udp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			turnLog("[TURN] %s", err)
			return
		}
		conn := rawConn.(*net.UDPConn)
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		dialer := &net.Dialer{Control: protectControl, Resolver: protectedResolver}
		conn, err2 := dialer.DialContext(ctx1, "tcp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			turnLog("[TURN] %s", err)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}

	cfg = &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Username:       user,
		Password:       pass,
		Conn:           turnConn,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	defer client.Close()

	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen on TURN client: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}

	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate TURN relay: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	defer func() {
		if closeErr := relayConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close relay connection: %s", closeErr)
			return
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	turnLog("[TURN] Allocated relay address: %s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(ctx)
	context.AfterFunc(turnctx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	defer turncancel()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1600)
		for {
			n, addr1, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				return
			}

			if addr1.String() != peer.String() {
				continue
			}

			_, err1 = conn2.WriteTo(buf[:n], peer)
			if err1 != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1600)
		for {
			n, _, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				return
			}

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				return
			}
		}
	}()

	wg.Wait()
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c chan<- error) {
	var err error = nil
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
	var conn1, conn2 net.PacketConn
	conn1, conn2 = connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		turnLog("[DTLS] Connection failed: %s", err)
		return
	}
	turnLog("[DTLS] Established DTLS connection!")
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
	}()
	if okchan != nil {
		go func() {
			for {
				select {
				case <-dtlsctx.Done():
					return
				case okchan <- struct{}{}:
				}
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		listenConn.SetDeadline(time.Now())
		dtlsConn.SetDeadline(time.Now())
	})
	var addr atomic.Value
	// Start read-loop on listenConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				return
			}
		}
	}()

	// Start read-loop on dtlsConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				return
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				return
			}
		}
	}()

	wg.Wait()
	listenConn.SetDeadline(time.Time{})
	dtlsConn.SetDeadline(time.Time{})
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	link string
	udp  bool
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c)
			if err := <-c; err != nil {
				turnLog("[STREAM %d] DTLS connection error: %s", streamID, err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, c)
				if err := <-c; err != nil {
					turnLog("[STREAM %d] TURN connection error: %s", streamID, err)
				}
			default:
			}
		}
	}
}

var currentTurnCancel context.CancelFunc
var turnMutex sync.Mutex
var okchan = make(chan struct{})

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddrC *C.char, vklinkC *C.char, n int, udp int, listenAddrC *C.char) int32 {
	peerAddr := C.GoString(peerAddrC)
	vklink := C.GoString(vklinkC)
	listenAddr := C.GoString(listenAddrC)

	turnLog("[PROXY] Starting with peer=%s, link=%s, listen=%s, n=%d, udp=%d", peerAddr, vklink, listenAddr, n, udp)

	turnMutex.Lock()
	defer turnMutex.Unlock()

	if currentTurnCancel != nil {
		currentTurnCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel

	peer, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		turnLog("[PROXY] Failed to resolve peer address: %v", err)
		return -1
	}

	parts := strings.Split(vklink, "join/")
	link := parts[len(parts)-1]
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}

	turnLog("[PROXY] Parsed VK link hash: %s", link)

	params := &turnParams{
		link: link,
		udp:  udp != 0,
	}

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		turnLog("[PROXY] Failed to listen on %s: %v", listenAddr, err)
		return -1
	}

	context.AfterFunc(ctx, func() {
		listenConn.Close()
	})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	connchan := make(chan net.PacketConn)
	t := time.Tick(100 * time.Millisecond)

	go func() {
		oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan, 0)
	}()

	go func() {
		oneTurnConnectionLoop(ctx, params, peer, connchan, t, 0)
	}()

	// Wait for at least one connection or timeout
	select {
	case <-okchan:
	case <-time.After(30 * time.Second):
		turnLog("[PROXY] Timeout waiting for first TURN connection")
		cancel()
		return -1
	case <-ctx.Done():
		return 0
	}

	for i := 0; i < n-1; i++ {
		streamID := i + 1
		cc := make(chan net.PacketConn)
		go func(id int) {
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, cc, nil, id)
		}(streamID)
		go func(id int) {
			oneTurnConnectionLoop(ctx, params, peer, cc, t, id)
		}(streamID)
	}

	return 0
}

//export wgTurnProxyStop
func wgTurnProxyStop() {
	turnMutex.Lock()
	defer turnMutex.Unlock()

	if currentTurnCancel != nil {
		turnLog("[PROXY] Stopping TURN proxy")
		currentTurnCancel()
		currentTurnCancel = nil
		turnLog("[PROXY] TURN proxy stopped")
	}
}
