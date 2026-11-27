/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

// Resolvers are the injected resolvers of the expensive values. A program
// built without them uses the ones backed by the agent's stores, see
// DefaultResolvers.
type Resolvers struct {
	// Signature verifies the signature of a module or an executable image.
	Signature *Resolver[signature.Key, *signature.Signature]
	// FileMeta provides the metadata of a file, e.g. if it is a DLL.
	FileMeta *Resolver[string, *fs.FileInfo]
	// ReverseDNS resolves the domain names of an IP address.
	ReverseDNS *Resolver[network.Address, DNSNames]
	// PE parses the PE file the directories selected by the options.
	PE *Resolver[PEKey, PEResult]
	// PEModified compares the PE file on disk with the image mapped in the
	// memory of the process to tell if the header was tampered with.
	PEModified *Resolver[PEModifiedKey, PEModifiedResult]
}

// PEOptions is the set of PE directories to parse. The directories are
// only parsed if some field of the expression needs them.
type PEOptions uint32

const (
	PESections PEOptions = 1 << iota
	PESymbols
	PEVersionResources
	PEImphash
	PECLR
	PESectionEntropy
)

// PEKey is the request to parse the PE file.
type PEKey struct {
	Path string
	Opts PEOptions
}

// PEResult is the outcome of parsing the PE file.
type PEResult struct {
	PE  *pe.PE
	Err error
}

// PEModifiedKey is the request to compare the PE file with the loaded image.
type PEModifiedKey struct {
	Path string
	PID  uint32
	Base uint64
	Opts PEOptions
}

// PEModifiedResult is the outcome of the comparison.
type PEModifiedResult struct {
	Modified bool
	Err      error
}

func (o PEOptions) parserOptions() []pe.Option {
	var opts []pe.Option
	if o&PESections != 0 {
		opts = append(opts, pe.WithSections())
	}
	if o&PESymbols != 0 {
		opts = append(opts, pe.WithSymbols())
	}
	if o&PEVersionResources != 0 {
		opts = append(opts, pe.WithVersionResources())
	}
	if o&PEImphash != 0 {
		opts = append(opts, pe.WithImphash())
	}
	if o&PECLR != 0 {
		opts = append(opts, pe.WithCLR())
	}
	if o&PESectionEntropy != 0 {
		opts = append(opts, pe.WithSectionEntropy())
	}
	return opts
}

// peOptions determines what aspects of the PE have to be parsed from the
// fields of the expression. The bound segments are disabled in the branch,
// so the section entropy is never requested, as it never was.
func peOptions(flds Fields, _ []Segment) uint32 {
	var o PEOptions
	for _, f := range flds {
		if f.Name.IsPeSection() || f.Name.IsPeModified() {
			o |= PESections
		}
		if f.Name.IsPeSymbol() {
			o |= PESymbols
		}
		if f.Name.IsPeVersionResource() || f.Name.IsPeVersionResources() {
			o |= PEVersionResources
		}
		if f.Name.IsPeImphash() {
			o |= PEImphash
		}
		if f.Name.IsPeDotnet() || f.Name.IsPeModified() {
			o |= PECLR
		}
		if f.Name.IsPeAnomalies() {
			o |= PESections | PESymbols
		}
	}
	return uint32(o)
}

// DNSNames is the outcome of a reverse DNS lookup.
type DNSNames struct {
	Names []string
	Err   error
}

var (
	reverseDNSOnce sync.Once
	reverseDNS     *network.ReverseDNS
)

// defaultResolvers are backed by the stores shared by the agent. They are
// reached lazily, so a program that never gets to the field never asks the
// store, and the reverse DNS cache isn't created unless a rule needs it.
var defaultResolvers = &Resolvers{
	Signature: NewResolver("signature", func(k signature.Key) *signature.Signature {
		return signature.GetSignatures().DoRequest(k)
	}),
	FileMeta: NewResolver("file_metadata", func(path string) *fs.FileInfo {
		return fs.GetMetadataStore().DoRequest(path)
	}),
	PE: NewResolver("pe", func(k PEKey) PEResult {
		p, err := pe.ParseFile(k.Path, k.Opts.parserOptions()...)
		return PEResult{PE: p, Err: err}
	}),
	PEModified: NewResolver("pe_modified", func(k PEModifiedKey) PEModifiedResult {
		file, err := pe.ParseFile(k.Path, k.Opts.parserOptions()...)
		if err != nil {
			return PEModifiedResult{Err: err}
		}
		mem, err := pe.ParseMem(k.PID, uintptr(k.Base), false, k.Opts.parserOptions()...)
		if err != nil {
			return PEModifiedResult{Err: err}
		}
		return PEModifiedResult{Modified: file.IsHeaderModified(mem)}
	}),
	ReverseDNS: NewResolver("reverse_dns", func(addr network.Address) DNSNames {
		reverseDNSOnce.Do(func() {
			reverseDNS = network.GetReverseDNS(2000, time.Minute*30, time.Minute*2)
		})
		names, err := reverseDNS.Add(addr)
		return DNSNames{Names: names, Err: err}
	}),
}

// DefaultResolvers returns the resolvers backed by the agent's stores.
func DefaultResolvers() *Resolvers { return defaultResolvers }
