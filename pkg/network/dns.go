/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package network

import (
	"errors"
	"expvar"
	"net"
	"sync"
	"time"
)

// ErrMaxNamesReached is thrown when the capacity of the names map is reached
var ErrMaxNamesReached = errors.New("dns reverse max names reached")

var (
	totalDNSLookups     = expvar.NewInt("dns.reverse.total.lookups")
	failedDNSLookups    = expvar.NewMap("dns.reverse.failed.lookups")
	expiredDNSNames     = expvar.NewInt("dns.reverse.expired.names")
	totalDNSNames       = expvar.NewInt("dns.reverse.total.names")
	cacheFullDNSLookups = expvar.NewInt("dns.reverse.cache.full.lookups")
)

// maxFailedDNSLookups designates the maximum number of failed DNS lookups
// after which the IP address is blacklisted
const maxFailedDNSLookups = 10

// ReverseDNS performs reverse DNS resolutions and keeps the cache of
// resolved IP to domain mappings.
type ReverseDNS struct {
	mux sync.Mutex
	// ttl specifies the time to live for each cache entry
	ttl time.Duration
	// size determines the maximum size of the domains cache
	size int

	domains map[Address]*dnsNames

	// blacklist contains the IP addresses that fail
	// to resolve after a number of attempts. We want to defend
	// ourselves from excessive reverse DNS lookup calls
	blacklist map[Address]int
	close     chan struct{}
}

type dnsNames struct {
	names      []string
	expiration int64
}

// NewReverseDNS creates a new DNS reverser with the specified size and TTL period.
func NewReverseDNS(size int, ttl, exp time.Duration) *ReverseDNS {
	reverseDNS := &ReverseDNS{
		domains:   make(map[Address]*dnsNames),
		blacklist: make(map[Address]int),
		size:      size,
		ttl:       ttl,
		close:     make(chan struct{}, 1),
	}

	tick := time.NewTicker(exp)
	go func() {
		for {
			select {
			case <-tick.C:
				reverseDNS.Expire()
			case <-reverseDNS.close:
				tick.Stop()
				return
			}
		}
	}()
	return reverseDNS
}

// Add performs a reverse lookup for the given address, returning a list
// of names mapping to that address. It assigns a ttl to the names value
// and puts it in the map. If the names map capacity is reached this method
// returns an error and gives up on adding new entries.
func (r *ReverseDNS) Add(addr Address) ([]string, error) {
	r.mux.Lock()
	defer r.mux.Unlock()

	if len(r.domains) > r.size {
		cacheFullDNSLookups.Add(1)
		return nil, ErrMaxNamesReached
	}

	if r.blacklist[addr] > maxFailedDNSLookups {
		return nil, nil
	}

	if names, ok := r.domains[addr]; ok {
		return names.names, nil
	}

	now := time.Now()
	exp := now.Add(r.ttl).UnixNano()
	names, err := net.LookupAddr(addr.ToIPString())
	if err != nil {
		r.blacklist[addr]++
		failedDNSLookups.Add(addr.ToIPString(), 1)
		return nil, err
	}

	totalDNSLookups.Add(1)
	totalDNSNames.Add(1)

	r.domains[addr] = &dnsNames{names: names, expiration: exp}

	return names, nil
}

// Get returns all the name mappings for the specified address.
func (r *ReverseDNS) Get(addr Address) []string {
	r.mux.Lock()
	defer r.mux.Unlock()

	names, ok := r.domains[addr]
	if !ok {
		return nil
	}

	return names.names
}

// Expire evicts name values that are eligible for expiration.
func (r *ReverseDNS) Expire() {
	deadline := time.Now().UnixNano()
	expired := int64(0)
	r.mux.Lock()

	for addr, val := range r.domains {
		if val.expiration > deadline {
			continue
		}
		expired++
		delete(r.domains, addr)
	}
	r.mux.Unlock()

	expiredDNSNames.Add(expired)
	totalDNSNames.Add(-expired)
}

// Len returns the size of the names map.
func (r *ReverseDNS) Len() int {
	r.mux.Lock()
	defer r.mux.Unlock()
	return len(r.domains)
}

// Close closes the expiration ticker.
func (r *ReverseDNS) Close() {
	r.close <- struct{}{}
}
