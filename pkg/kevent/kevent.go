/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package kevent

import (
	"fmt"
	"strings"
	"sync"
	"time"

	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/hostname"
)

// pool is used to alleviate the pressure on the heap allocator
var pool = sync.Pool{
	New: func() interface{} {
		return &Kevent{}
	},
}

// TimestampFormat is the Go valid format for the kernel event timestamp
var TimestampFormat string

// MetadataKey represents the type definition for the metadata keys
type MetadataKey string

// Metadata is a type alias for event metadata. Any tag, i.e. key/value pair could be attached to metadata.
type Metadata map[MetadataKey]string

const (
	// YaraMatchesKey is the tag name for the yara matches JSON representation
	YaraMatchesKey MetadataKey = "yara.matches"
	// RuleNameKey identifies the rule that was triggered by the event
	RuleNameKey MetadataKey = "rule.name"
	// RuleGroupKey identifies the group to which the triggered rule pertains
	RuleGroupKey MetadataKey = "rule.group"
)

func (key MetadataKey) String() string { return string(key) }

// String turns kernel event's metadata into string.
func (md Metadata) String() string {
	var sb strings.Builder
	for k, v := range md {
		sb.WriteString(k.String() + ": " + v + ", ")
	}
	return strings.TrimSuffix(sb.String(), ", ")
}

// Kevent encapsulates kernel event's payload.
type Kevent struct {
	// Seq is monotonically incremented kernel event sequence.
	Seq uint64 `json:"seq"`
	// PID is the identifier of the process that generated the event.
	PID uint32 `json:"pid"`
	// Tid is the thread identifier of the thread that generated the event.
	Tid uint32 `json:"tid"`
	// Type is the internal representation of the kernel event. This field should be ignored by serializers.
	Type ktypes.Ktype `json:"-"`
	// CPU designates the processor logical core where the event was originated.
	CPU uint8 `json:"cpu"`
	// Name is the human friendly name of the kernel event.
	Name string `json:"name"`
	// Category designates the category to which this event pertains.
	Category ktypes.Category `json:"category"`
	// Description is the short explanation that describes the purpose of the event.
	Description string `json:"description"`
	// Host is the machine name that reported the generated event.
	Host string `json:"host"`
	// Timestamp represents the temporal occurrence of the event.
	Timestamp time.Time `json:"timestamp"`
	// Kparams stores the collection of kernel event parameters.
	Kparams Kparams `json:"params"`
	// Metadata represents any tags that are meaningful to this event.
	Metadata Metadata `json:"metadata"`
	// PS represents process' metadata and its allocated resources such as handles, DLLs, etc.
	PS *pstypes.PS `json:"ps,omitempty"`
}

// String returns event's string representation.
func (kevt *Kevent) String() string {
	if kevt.PS != nil {
		return fmt.Sprintf(`
		Seq: %d
		Pid: %d
		Tid: %d
		Type: %s
		CPU: %d
		Name: %s
		Category: %s
		Description: %s
		Host: %s,
		Timestamp: %s,
		Kparams: %s,
		Metadata: %s,
	    %s
	`,
			kevt.Seq,
			kevt.PID,
			kevt.Tid,
			kevt.Type,
			kevt.CPU,
			kevt.Name,
			kevt.Category,
			kevt.Description,
			kevt.Host,
			kevt.Timestamp,
			kevt.Kparams,
			kevt.Metadata,
			kevt.PS,
		)
	}
	return fmt.Sprintf(`
		Seq: %d
		Pid: %d
		Tid: %d
		Type: %s
		CPU: %d
		Name: %s
		Category: %s
		Description: %s
		Host: %s,
		Timestamp: %s,
		Kparams: %s,
		Metadata: %s
	`,
		kevt.Seq,
		kevt.PID,
		kevt.Tid,
		kevt.Type,
		kevt.CPU,
		kevt.Name,
		kevt.Category,
		kevt.Description,
		kevt.Host,
		kevt.Timestamp,
		kevt.Kparams,
		kevt.Metadata,
	)
}

// New constructs a new kernel event instance.
func New(seq uint64, pid, tid uint32, cpu uint8, ktype ktypes.Ktype, ts time.Time, kpars Kparams) *Kevent {
	kevt := pool.Get().(*Kevent)
	metainfo := ktypes.KtypeToKeventInfo(ktype)
	*kevt = Kevent{
		Seq:         seq,
		PID:         pid,
		Tid:         tid,
		CPU:         cpu,
		Type:        ktype,
		Category:    metainfo.Category,
		Name:        metainfo.Name,
		Description: metainfo.Description,
		Timestamp:   ts,
		Kparams:     kpars,
		Metadata:    make(map[MetadataKey]string),
		Host:        hostname.Get(),
	}
	return kevt
}

// Empty return a pristine kernel event instance.
func Empty() *Kevent {
	return &Kevent{
		Kparams:  map[string]*Kparam{},
		Metadata: make(map[MetadataKey]string),
		PS:       &pstypes.PS{},
	}
}

// NewFromKcap recovers the kernel event instance from the kcapture byte buffer.
func NewFromKcap(buf []byte) (*Kevent, error) {
	kevt := &Kevent{
		Kparams:  make(Kparams),
		Metadata: make(map[MetadataKey]string),
	}
	if err := kevt.UnmarshalRaw(buf, kcapver.KevtSecV1); err != nil {
		return nil, err
	}
	return kevt, nil
}

// AddMeta appends a key/value pair to event's metadata.
func (kevt *Kevent) AddMeta(k MetadataKey, v string) {
	kevt.Metadata[k] = v
}

// Release returns an event to the pool.
func (kevt *Kevent) Release() {
	for _, kpar := range kevt.Kparams {
		kpar.Release()
	}
	*kevt = Kevent{} // clear kevent
	pool.Put(kevt)
}
