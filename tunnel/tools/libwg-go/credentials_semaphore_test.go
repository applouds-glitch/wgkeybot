/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func setupCredentialSemaphoreTest(t *testing.T) {
	t.Helper()
	previousCapacity, previousFetch := streamsPerCredValue(), globalGetCreds
	forgetTurnCreds()
	setStreamsPerCred(4)
	t.Cleanup(func() {
		forgetTurnCreds()
		setStreamsPerCred(previousCapacity)
		globalGetCreds = previousFetch
	})
}

func awaitCredentialSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// The wrapper observes entry/exit only: every worker still uses the real
// getCredsCached, its slot mutex and its semaphore. Before the fix, the fetch
// and its sibling waiting on the same lock occupied both outer worker tokens.
func TestCredentialSemaphoreCacheHitPastBlockedSlot(t *testing.T) {
	setupCredentialSemaphoreTest(t)
	resetNetworkSwitch(t)
	resetNetworkAvailabilityForTest()
	t.Cleanup(resetNetworkAvailabilityForTest)
	if _, _, _, err := getCredsCached(context.Background(), "cached", 4, vkCreds("cached-user")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cachedCtx, cachedCancel := context.WithCancel(ctx)
	entered := make(chan struct{})
	called := make(chan struct{}, 2)
	hit := make(chan error, 1)
	globalGetCreds = func(ctx context.Context, link string, streamID int) (string, string, []string, error) {
		if link == "blocked" {
			called <- struct{}{}
		}
		u, p, a, err := getCredsCached(ctx, link, streamID, func(ctx context.Context, link string) (string, string, []string, int, error) {
			if link != "blocked" {
				return "", "", nil, 0, errors.New("cached slot unexpectedly fetched")
			}
			close(entered)
			<-ctx.Done()
			return "", "", nil, 0, ctx.Err()
		})
		if link == "cached" {
			cachedCancel() // stop before a successful cache hit could dial
			if err == nil && u != "cached-user" {
				err = errors.New("wrong cached credential")
			}
			hit <- err
			return "", "", nil, ctx.Err()
		}
		return u, p, a, err
	}
	var workers sync.WaitGroup
	start := func(ctx context.Context, group, id int, link string) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runWorker(ctx, WorkerGroupConfig{GroupID: group, Link: link, UseUDP: true}, &stream{id: id}, 0)
		}()
	}
	t.Cleanup(func() {
		cancel()
		cachedCancel()
		workers.Wait()
	})
	start(ctx, 0, 0, "blocked")
	awaitCredentialSignal(t, entered, "the first slot's blocked fetch")
	awaitCredentialSignal(t, called, "the first worker's lookup")
	start(ctx, 0, 1, "blocked")
	awaitCredentialSignal(t, called, "the sibling's lookup under the held slot lock")
	start(cachedCtx, 1, 4, "cached")
	select {
	case err := <-hit:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cached worker blocked behind a fetch and its sibling's slot lock")
	}
}

// Signals when getCredsCached evaluates Done in its semaphore select. This
// orders the third caller without a scheduling sleep or a production hook.
type credentialWaitContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *credentialWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.checked) })
	return c.Context.Done()
}

func TestCredentialSemaphoreBoundsRealFetches(t *testing.T) {
	setupCredentialSemaphoreTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	var calls sync.WaitGroup
	t.Cleanup(func() { cancel(); calls.Wait() })
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	fn := func(ctx context.Context, link string) (string, string, []string, int, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return link, "pass", credsRelays, 60, nil
		case <-ctx.Done():
			return "", "", nil, 0, ctx.Err()
		}
	}
	start := func(ctx context.Context, slot int) <-chan error {
		done := make(chan error, 1)
		calls.Add(1)
		go func() {
			defer calls.Done()
			_, _, _, err := getCredsCached(ctx, "link", slot*streamsPerCredValue(), fn)
			done <- err
		}()
		return done
	}
	first := start(ctx, 0)
	awaitCredentialSignal(t, entered, "fetch 1")
	second := start(ctx, 1)
	awaitCredentialSignal(t, entered, "fetch 2")
	thirdCtx := &credentialWaitContext{Context: ctx, checked: make(chan struct{})}
	third := start(thirdCtx, 2)
	awaitCredentialSignal(t, thirdCtx.checked, "fetch 3 reaching the semaphore")
	select {
	case <-entered:
		t.Fatal("three real fetches entered fn while both tokens were occupied")
	case <-time.After(200 * time.Millisecond):
	}
	// One fetch returns; only then may the third enter. The other stays blocked.
	release <- struct{}{}
	awaitCredentialSignal(t, entered, "fetch 3 after one token was released")
	close(release)
	for _, done := range []<-chan error{first, second, third} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("fetch did not finish after release")
		}
	}
}

func TestCredentialSemaphoreTokenWaitCancels(t *testing.T) {
	setupCredentialSemaphoreTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	var calls sync.WaitGroup
	t.Cleanup(func() { cancel(); calls.Wait() })
	entered := make(chan struct{}, 2)
	for slot := 0; slot < 2; slot++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			getCredsCached(ctx, "blocked", slot*streamsPerCredValue(), func(ctx context.Context, _ string) (string, string, []string, int, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return "", "", nil, 0, ctx.Err()
			})
		}()
	}
	awaitCredentialSignal(t, entered, "first occupied token")
	awaitCredentialSignal(t, entered, "second occupied token")
	waitCtx, stopWaiting := context.WithCancel(ctx)
	defer stopWaiting()
	observed := &credentialWaitContext{Context: waitCtx, checked: make(chan struct{})}
	done := make(chan error, 1)
	unexpectedFetch := errors.New("fetch ran without waiting for a token")
	calls.Add(1)
	go func() {
		defer calls.Done()
		_, _, _, err := getCredsCached(observed, "third", 2*streamsPerCredValue(), func(context.Context, string) (string, string, []string, int, error) {
			return "", "", nil, 0, unexpectedFetch
		})
		done <- err
	}()
	awaitCredentialSignal(t, observed.checked, "the token wait")
	select {
	case err := <-done:
		t.Fatalf("caller returned before cancellation while both tokens were occupied: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	stopWaiting()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled token wait returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled caller stayed blocked waiting for a token")
	}
}
