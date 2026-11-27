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

package fields

import "strings"

// Source identifies the place a field value is read from. It is fixed by
// the field name, so the compiler can bind a field to its source once
// instead of probing every source for every event.
type Source uint8

const (
	// SourceNone is the source of the fields nobody serves. Such
	// a field always evaluates to the default value of its type.
	SourceNone Source = iota
	// SourceEvent serves the generic event fields (evt.*, kevt.*).
	SourceEvent
	// SourceProcess serves the process state fields (ps.*) except
	// the ones backed by the PE metadata.
	SourceProcess
	// SourcePE serves the PE metadata (pe.*, ps.pe.*) and the
	// signature of the process executable (ps.signature.*).
	SourcePE
	// SourceThread serves the thread fields (thread.*).
	SourceThread
	// SourceFile serves the file fields (file.*).
	SourceFile
	// SourceModule serves the module fields (module.*, image.*, dll.*).
	SourceModule
	// SourceRegistry serves the registry fields (registry.*).
	SourceRegistry
	// SourceNetwork serves the network fields (net.*).
	SourceNetwork
	// SourceMemory serves the memory fields (mem.*).
	SourceMemory
	// SourceDNS serves the DNS fields (dns.*).
	SourceDNS

	// NumSources is the number of sources, including SourceNone.
	NumSources
)

var sourceNames = [NumSources]string{
	SourceNone:     "none",
	SourceEvent:    "event",
	SourceProcess:  "process",
	SourcePE:       "pe",
	SourceThread:   "thread",
	SourceFile:     "file",
	SourceModule:   "module",
	SourceRegistry: "registry",
	SourceNetwork:  "network",
	SourceMemory:   "memory",
	SourceDNS:      "dns",
}

// String returns the source name.
func (s Source) String() string {
	if s >= NumSources {
		return "unknown"
	}
	return sourceNames[s]
}

// sourcePrefixes is the hand written routing table. The first matching
// prefix wins, so the more specific prefixes have to precede the general
// ones: ps.pe. and ps.signature. are read from the PE metadata, even though
// they live in the ps. namespace.
var sourcePrefixes = [...]struct {
	prefix string
	source Source
}{
	{"ps.pe.", SourcePE},
	{"ps.signature.", SourcePE},
	{"ps.", SourceProcess},
	{"pe.", SourcePE},
	{"evt.", SourceEvent},
	{"kevt.", SourceEvent},
	{"thread.", SourceThread},
	{"file.", SourceFile},
	{"module.", SourceModule},
	{"image.", SourceModule},
	{"dll.", SourceModule},
	{"registry.", SourceRegistry},
	{"net.", SourceNetwork},
	{"mem.", SourceMemory},
	{"dns.", SourceDNS},
}

// Source returns the source the field value is read from.
func (f Field) Source() Source {
	s := string(f)
	for _, p := range sourcePrefixes {
		if strings.HasPrefix(s, p.prefix) {
			return p.source
		}
	}
	return SourceNone
}

// Def is the definition of a field: the metadata plus the compile time
// attributes the compiler binds the field with.
type Def struct {
	FieldInfo
	// Source is where the field value is read from.
	Source Source
}

// Lookup returns the definition of the field. The second result is false
// if the field isn't declared.
func Lookup(f Field) (Def, bool) {
	info, ok := fields[f]
	if !ok {
		return Def{}, false
	}
	return Def{FieldInfo: info, Source: f.Source()}, true
}

// Defs returns the definitions of all the declared fields ordered by name.
func Defs() []Def {
	infos := Get()
	defs := make([]Def, 0, len(infos))
	for _, info := range infos {
		defs = append(defs, Def{FieldInfo: info, Source: info.Field.Source()})
	}
	return defs
}
