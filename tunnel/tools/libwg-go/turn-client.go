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

var turnLogger = &AndroidLogger{level: C.ANDROID_LOG_INFO, tag: cstring("WireGuard/TurnClient")}

func turnLog(format string, args ...interface{}) {
	turnLogger.Printf(format, args...)
}

func protectControl(network, address string, c syscall.RawConn) error {
	turnLog("[PROTECT] Protecting socket: network=%s address=%s", network, address)
	err := c.Control(func(fd uintptr) {
		ret := C.wgProtectSocket(C.int(fd))
		if ret != 0 {
			turnLog("[PROTECT] ERROR: wgProtectSocket(fd=%d) returned %d", fd, ret)
		} else {
			turnLog("[PROTECT] Socket fd=%d protected successfully", fd)
		}
	})
	if err != nil {
		turnLog("[PROTECT] ERROR: Control callback failed: %v", err)
	}
	return err
}

func getProtectedClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   protectControl,
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout:   10 * time.Second,
							Control:   protectControl,
						}
						// Use public DNS to bypass VPN
						dnsAddr := "8.8.8.8:53"
						return d.DialContext(ctx, "udp", dnsAddr)
					},
				},
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func getVkCreds(link string) (string, string, string, error) {
	doRequest := func(data string, url string, stepName string) (resp map[string]interface{}, err error) {
		turnLog("[VK CREDS] Step %s: requesting %s", stepName, url)
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

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		turnLog("[VK CREDS] Step %s: request completed successfully", stepName)
		return resp, nil
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			turnLog("[VK CREDS] get TURN creds panic: %v\n", r)
		}
	}()

	turnLog("[VK CREDS] Starting VK authentication process")

	// Step 1: Get initial anonym token
	data := "client_secret=QbYic1K3lEV5kTGiqlq2&client_id=6287487&scopes=audio_anonymous%2Cvideo_anonymous%2Cphotos_anonymous%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, err := doRequest(data, url, "1/5 - initial token")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	tokenData, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing data")
	}
	token1 := tokenData["access_token"].(string)
	turnLog("[VK CREDS] Step 1/5: received initial token")

	// Step 2: Get anonymous access token payload
	data = fmt.Sprintf("access_token=%s", token1)
	url = "https://api.vk.ru/method/calls.getAnonymousAccessTokenPayload?v=5.264&client_id=6287487"

	resp, err = doRequest(data, url, "2/5 - payload")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	responseField, ok := resp["response"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing response field")
	}
	token2 := responseField["payload"].(string)
	turnLog("[VK CREDS] Step 2/5: received payload token")

	// Step 3: Get messages token
	data = fmt.Sprintf("client_id=6287487&token_type=messages&payload=%s&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487", token2)
	url = "https://login.vk.ru/?act=get_anonym_token"

	resp, err = doRequest(data, url, "3/5 - messages token")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	tokenData, ok = resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing data field in 3rd step")
	}
	token3 := tokenData["access_token"].(string)
	turnLog("[VK CREDS] Step 3/5: received messages token")

	// Step 4: Get calls token
	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s", link, token3)
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264"

	resp, err = doRequest(data, url, "4/5 - calls token")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	responseField, ok = resp["response"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("invalid response from vk: missing response field in 4th step")
	}
	token4 := responseField["token"].(string)
	turnLog("[VK CREDS] Step 4/5: received calls token")

	// Step 5: Get session key from OK
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url, "5/5 - session key")
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token5 := resp["session_key"].(string)
	turnLog("[VK CREDS] Step 5/5: received session key from OK")

	// Join conversation and get TURN credentials
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token4, token5)
	url = "https://calls.okcdn.ru/fb.do"

	turnLog("[VK CREDS] Requesting TURN server credentials")
	resp, err = doRequest(data, url, "TURN credentials")
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

	turnLog("[VK CREDS] Successfully received TURN credentials: username=%s, server=%s", user, address)
	return user, pass, address, nil
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	turnLog("[DTLS] Generating self-signed certificate")
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}
	turnLog("[DTLS] Certificate generated successfully")
	
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	
	turnLog("[DTLS] Starting handshake with %s", peer.String())
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS client: %w", err)
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, fmt.Errorf("DTLS handshake failed: %w", err)
	}
	
	turnLog("[DTLS] Handshake completed successfully with %s", peer.String())
	return dtlsConn, nil
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
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		turnLog("[DTLS] Closed DTLS connection")
	}()
	turnLog("[DTLS] Established DTLS connection!")
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
				turnLog("[DTLS] ReadFrom listenConn error: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				turnLog("[DTLS] Write to DTLS error: %s", err1)
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
				turnLog("[DTLS] Read from DTLS error: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				turnLog("[DTLS] Read error: no listener ip")
				return
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				turnLog("[DTLS] WriteTo listenConn error: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	turnLog("[DTLS] DTLS connection finished")
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
	host string
	port string
	link string
	udp  bool
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	var err error = nil
	defer func() { c <- err }()
	
	turnLog("[TURN] Starting TURN connection")
	user, pass, url, err1 := getVkCreds(turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	turnLog("[TURN] Received TURN credentials: username=%s", user)
	
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	
	protocol := "TCP"
	if turnParams.udp {
		protocol = "UDP"
	}
	turnLog("[TURN] Connecting to TURN server %s via %s", turnServerAddr, protocol)

	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		dialer := &net.Dialer{
			Control: protectControl,
		}
		rawConn, err2 := dialer.DialContext(ctx1, "udp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			turnLog("[TURN] %s", err)
			return
		}
		conn := rawConn.(*net.UDPConn)
		turnLog("[TURN] UDP connection established to TURN server")
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		dialer := &net.Dialer{
			Control: protectControl,
		}
		conn, err2 := dialer.DialContext(ctx1, "tcp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			turnLog("[TURN] %s", err)
			return
		}
		turnLog("[TURN] TCP connection established to TURN server")
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
		turnLog("[TURN] Using IPv4 address family")
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
		turnLog("[TURN] Using IPv6 address family")
	}
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	turnLog("[TURN] Creating TURN client")
	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	defer client.Close()

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	turnLog("[TURN] TURN client listening")

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	turnLog("[TURN] Allocating relay socket on TURN server")
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		turnLog("[TURN] %s", err)
		return
	}
	turnLog("[TURN] Relay socket allocated successfully")
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
			return
		}
		turnLog("[TURN] Closed TURN allocated connection")
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	turnLog("[TURN] relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(ctx)
	context.AfterFunc(turnctx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	var addr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				turnLog("[TURN] ReadFrom conn2 error: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				turnLog("[TURN] WriteTo relayConn error: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on relayConn
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				turnLog("[TURN] ReadFrom relayConn error: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				turnLog("[TURN] Read error: no listener ip")
				return
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				turnLog("[TURN] WriteTo conn2 error: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	turnLog("[TURN] TURN connection finished")
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	turnLog("[STREAM %d] Starting DTLS connection loop", streamID)
	for {
		select {
		case <-ctx.Done():
			turnLog("[STREAM %d] DTLS connection loop stopped (context done)", streamID)
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			turnLog("[STREAM %d] Starting new DTLS connection", streamID)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c)
			if err := <-c; err != nil {
				turnLog("[STREAM %d] DTLS connection error: %s", streamID, err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time, streamID int) {
	turnLog("[STREAM %d] Starting TURN connection loop", streamID)
	for {
		select {
		case <-ctx.Done():
			turnLog("[STREAM %d] TURN connection loop stopped (context done)", streamID)
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				turnLog("[STREAM %d] Starting new TURN connection", streamID)
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

//export wgTurnProxyStart
func wgTurnProxyStart(peerAddr string, vklink string, n int, udp bool, listenAddr string) int32 {
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

	params := &turnParams{
		host: "",
		port: "",
		link: link,
		udp:  udp,
	}

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		turnLog("[PROXY] Failed to listen on %s: %v", listenAddr, err)
		return -1
	}
	turnLog("[PROXY] Listening on %s", listenAddr)

	context.AfterFunc(ctx, func() {
		listenConn.Close()
		turnLog("[PROXY] Local UDP listener closed")
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

	okchan := make(chan struct{})
	connchan := make(chan net.PacketConn)
	t := time.Tick(100 * time.Millisecond)

	turnLog("[PROXY] Starting stream 0 (initial connection)")
	go func() {
		oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan, 0)
	}()

	go func() {
		oneTurnConnectionLoop(ctx, params, peer, connchan, t, 0)
	}()

	// Wait for at least one connection or timeout
	select {
	case <-okchan:
		turnLog("[PROXY] First TURN connection established")
	case <-time.After(30 * time.Second):
		turnLog("[PROXY] Timeout waiting for first TURN connection")
	case <-ctx.Done():
		turnLog("[PROXY] Proxy stopped during initial connection")
		return 0
	}

	turnLog("[PROXY] Starting additional %d streams", n-1)
	for i := 0; i < n-1; i++ {
		streamID := i + 1
		cc := make(chan net.PacketConn)
		turnLog("[PROXY] Starting stream %d", streamID)
		go func(id int) {
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, cc, nil, id)
		}(streamID)
		go func(id int) {
			oneTurnConnectionLoop(ctx, params, peer, cc, t, id)
		}(streamID)
	}
	turnLog("[PROXY] All %d streams started", n)

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
