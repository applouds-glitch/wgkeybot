/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"sync"
)

type credentialAllocationKey struct{ user, pass string }

type credentialAllocationSlots struct {
	tokens chan struct{}
	refs   int // holders plus waiters; guarded by credentialAllocations.Mutex
}

// Shared across groups and proxy restarts: a cancelled session can still be
// closing its allocations when the next session reuses the same credentials.
// Credential invalidation must not reset these leases.
var credentialAllocations = struct {
	sync.Mutex
	byCred map[credentialAllocationKey]*credentialAllocationSlots
}{byCred: make(map[credentialAllocationKey]*credentialAllocationSlots)}

// Reserve before dialing, and hold until the allocation and its transport have
// closed. This also counts failover racers, so ten workers cannot temporarily
// exceed ten allocations by dialing several backup servers at once.
func acquireCredentialAllocation(ctx context.Context, user, pass string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := credentialAllocationKey{user, pass}
	credentialAllocations.Lock()
	slots := credentialAllocations.byCred[key]
	if slots == nil {
		slots = &credentialAllocationSlots{tokens: make(chan struct{}, maxStreamsPerCredential)}
		credentialAllocations.byCred[key] = slots
	}
	slots.refs++
	credentialAllocations.Unlock()

	unref := func() {
		credentialAllocations.Lock()
		slots.refs--
		if slots.refs == 0 {
			delete(credentialAllocations.byCred, key)
		}
		credentialAllocations.Unlock()
	}
	select {
	case slots.tokens <- struct{}{}:
	case <-ctx.Done():
		unref()
		return nil, ctx.Err()
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			<-slots.tokens
			unref()
		})
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
