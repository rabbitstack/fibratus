/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package action

import (
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"sync"
)

var (
	inboundAllowRuleID  = wf.RuleID(windows.GUID{Data1: 0xcc2d6ce, Data2: 0xe747, Data3: 0x4480, Data4: [8]byte{0x9b, 0xbd, 0x7f, 0xa8, 0x99, 0xb7, 0xb1, 0x9a}})
	outboundAllowRuleID = wf.RuleID(windows.GUID{Data1: 0x4480ae, Data2: 0x9b7f, Data3: 0xa899, Data4: [8]byte{0xbd, 0x9b, 0xa8, 0xb7, 0x7f, 0x99, 0xe7, 0x1a}})
	inboundDenyRuleID   = wf.RuleID(windows.GUID{Data1: 0x7f9bbc, Data2: 0x99b7, Data3: 0xe747, Data4: [8]byte{0x9a, 0x9b, 0xa8, 0xbd, 0x44, 0x80, 0xcc, 0xc1}})
	outboundDenyRuleID  = wf.RuleID(windows.GUID{Data1: 0xbd9bda, Data2: 0x7fa8, Data3: 0x99b7, Data4: [8]byte{0xcc, 0x44, 0x9a, 0x9b, 0xe7, 0x77, 0x47, 0xd1}})
)

var (
	// inboundAllowRuleName denotes the firewall rule name for allowed inbound traffic
	inboundAllowRuleName = "Fibratus Allow (Inbound)"
	// outboundAllowRuleName denotes the firewall rule name for allowed outbound traffic
	outboundAllowRuleName = "Fibratus Allow (Outbound)"
	// inboundDenyRuleName denotes the firewall rule name for isolated inbound traffic
	inboundDenyRuleName = "Fibratus Isolate (Inbound)"
	// outboundDenyRuleName denotes the firewall rule name for isolated outbound traffic
	outboundDenyRuleName = "Fibratus Isolate (Outbound)"
)

type firewall struct {
	s        *wf.Session
	mu       sync.Mutex
	inbound  *wf.Rule // rule for allowed inbound traffic
	outbound *wf.Rule // rule for allowed outbound traffic
}

func newFirewall() (*firewall, error) {
	opts := &wf.Options{}

	sess, err := wf.New(opts)
	if err != nil {
		return nil, err
	}

	return &firewall{s: sess}, nil
}

func (f *firewall) allow(whitelist []net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inbound = &wf.Rule{
		ID:     inboundAllowRuleID,
		Name:   inboundAllowRuleName,
		Layer:  wf.LayerInboundIPPacketV4,
		Action: wf.ActionPermit,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.AddrFrom4([4]byte{127, 0, 0, 1})},
			{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.AddrFrom4([4]byte{127, 0, 0, 1})},
		},
	}

	f.outbound = &wf.Rule{
		ID:     outboundAllowRuleID,
		Name:   outboundAllowRuleName,
		Layer:  wf.LayerOutboundIPPacketV4,
		Action: wf.ActionPermit,
		Conditions: []*wf.Match{
			{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: netip.AddrFrom4([4]byte{127, 0, 0, 1})},
			{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.AddrFrom4([4]byte{127, 0, 0, 1})},
		},
	}

	for _, addr := range whitelist {
		f.addIPCondition(addr)
	}

	return multierror.Wrap(f.s.AddRule(f.inbound), f.s.AddRule(f.outbound))
}

func (f *firewall) deny() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	in := &wf.Rule{
		ID:     inboundDenyRuleID,
		Name:   inboundDenyRuleName,
		Layer:  wf.LayerInboundIPPacketV4,
		Action: wf.ActionBlock,
	}

	out := &wf.Rule{
		ID:     outboundDenyRuleID,
		Name:   outboundDenyRuleName,
		Layer:  wf.LayerOutboundIPPacketV4,
		Action: wf.ActionBlock,
	}

	return multierror.Wrap(f.s.AddRule(in), f.s.AddRule(out))
}

func (f *firewall) findAllowRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.inbound != nil && f.outbound != nil {
		return nil
	}
	rules, err := f.s.Rules()
	if err != nil {
		return err
	}

	for _, rule := range rules {
		switch rule.ID {
		case inboundAllowRuleID:
			f.inbound = rule
		case outboundAllowRuleID:
			f.outbound = rule
		}
		if f.inbound != nil && f.outbound != nil {
			break
		}
	}

	return nil
}

func (f *firewall) removeAllowRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return multierror.Wrap(f.s.DeleteRule(inboundAllowRuleID), f.s.DeleteRule(outboundAllowRuleID))
}

func (f *firewall) hasAllowRules() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inbound != nil && f.outbound != nil
}

func (f *firewall) addIPCondition(addr net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip := netip.AddrFrom4([4]byte(addr))
	f.inbound.Conditions = append(f.inbound.Conditions, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: ip})
	f.inbound.Conditions = append(f.inbound.Conditions, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ip})
	f.outbound.Conditions = append(f.outbound.Conditions, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: ip})
	f.outbound.Conditions = append(f.outbound.Conditions, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ip})
}

func (f *firewall) hasIPCondition(addr net.IP) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.inbound.Conditions {
		if c.Field != wf.FieldIPLocalAddress && c.Field != wf.FieldIPRemoteAddress {
			continue
		}

		address, ok := c.Value.(netip.Addr)
		if !ok {
			continue
		}

		if netip.AddrFrom4([4]byte(addr)) == address {
			return true
		}
	}

	for _, c := range f.outbound.Conditions {
		if c.Field != wf.FieldIPLocalAddress && c.Field != wf.FieldIPRemoteAddress {
			continue
		}

		address, ok := c.Value.(netip.Addr)
		if !ok {
			continue
		}

		if netip.AddrFrom4([4]byte(addr)) == address {
			return true
		}
	}

	return false
}

var fw *firewall

// Isolate talks to the WFP (Windows Filtering Platform) engine to
// set up firewall rules that result in complete host isolation.
// The traffic is allowed for the IP addresses specified in the
// permitted parameter.
// If the firewall rules already exist and the whitelist IP addresses
// are given, the rules are first removed and then recreated with the new
// allowed IP set.
func Isolate(whitelist []net.IP) error {
	if fw == nil {
		var err error
		fw, err = newFirewall()
		if err != nil {
			return err
		}
	}

	if err := fw.findAllowRules(); err != nil {
		return err
	}

	switch {
	case fw.hasAllowRules() && len(whitelist) > 0:
		// rules were added and the whitelist
		// is given in the action. Check if
		// the given permitted addresses contain
		// an item that is not already in the
		// allowed rules conditions.
		refresh := true
		for _, addr := range whitelist {
			if fw.hasIPCondition(addr) {
				refresh = false
				break
			} else {
				fw.addIPCondition(addr)
			}
		}

		if refresh {
			if err := fw.removeAllowRules(); err != nil {
				return err
			}
			return fw.allow(whitelist)
		}

		return nil
	case fw.hasAllowRules():
		// rules were added and no new permitted
		// addresses are supplied in the action
		return nil
	default:
		// rules were not added, so we set up
		// the rule to allow localhost in/out
		// traffic in addition to permitted
		// IP address.
		// Block the remaining in/out traffic
		if err := fw.allow(whitelist); err != nil {
			return err
		}
		return fw.deny()
	}
}
