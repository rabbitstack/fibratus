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
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"strings"
	"sync"
	"time"
)

// pool is used to alleviate the pressure on the heap allocator
var pool = sync.Pool{
	New: func() interface{} {
		return &Kevent{}
	},
}

// TimestampFormat is the Go valid format for the event timestamp
var TimestampFormat string

// MetadataKey represents the type definition for the metadata keys
type MetadataKey string

// Metadata is a type alias for event metadata. Any tag, i.e. key/value pair could be attached to metadata.
type Metadata map[MetadataKey]any

const (
	// YaraMatchesKey is the tag name for the yara matches JSON representation
	YaraMatchesKey MetadataKey = "yara.matches"
	// RuleNameKey identifies the rule that was triggered by the event
	RuleNameKey MetadataKey = "rule.name"
	// RuleGroupKey identifies the group to which the triggered rule pertains
	RuleGroupKey MetadataKey = "rule.group"
	// RuleSequenceByKey represents the join field value in sequence rules
	RuleSequenceByKey MetadataKey = "rule.seq.by"
)

func (key MetadataKey) String() string { return string(key) }

// String turns kernel event's metadata into string.
func (md Metadata) String() string {
	var sb strings.Builder
	for k, v := range md {
		sb.WriteString(k.String() + ": " + fmt.Sprintf("%s", v) + ", ")
	}
	return strings.TrimSuffix(sb.String(), ", ")
}

// Kevent encapsulates event's state and provides a set of methods for
// accessing and manipulating event parameters, process state, and other
// metadata.
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
	// WaitEnqueue indicates if this event should temporarily defer pushing to
	// the consumer output queue. This is usually required in event processors
	// to propagate certain events when the related event arrives, and it is replaced
	// by the event that was temporarily stored in processor's state.
	WaitEnqueue bool `json:"waitenqueue"`
	// Delayed indicates if this event should be enqueued in aggregator backlog.
	// Backlog stores events that await for the acknowledgement from subsequent
	// events.
	Delayed bool `json:"delayed"`
}

// DelayKey returns the value that is used to
// store and reference delayed events in the event
// backlog state. The delayed event is indexed by
// the sequence identifier.
func (e *Kevent) DelayKey() uint64 {
	switch e.Type {
	case ktypes.CreateHandle, ktypes.CloseHandle:
		return e.Kparams.MustGetUint64(kparams.HandleObject)
	}
	return 0
}

// String returns event's string representation.
func (e *Kevent) String() string {
	if e.PS != nil {
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
			e.Seq,
			e.PID,
			e.Tid,
			e.Type,
			e.CPU,
			e.Name,
			e.Category,
			e.Description,
			e.Host,
			e.Timestamp,
			e.Kparams,
			e.Metadata,
			e.PS,
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
		e.Seq,
		e.PID,
		e.Tid,
		e.Type,
		e.CPU,
		e.Name,
		e.Category,
		e.Description,
		e.Host,
		e.Timestamp,
		e.Kparams,
		e.Metadata,
	)
}

// Empty return a pristine event instance.
func Empty() *Kevent {
	return &Kevent{
		Kparams:  map[string]*Kparam{},
		Metadata: make(map[MetadataKey]any),
		PS:       &pstypes.PS{},
	}
}

// NewFromKcap recovers the event instance from the capture byte buffer.
func NewFromKcap(buf []byte) (*Kevent, error) {
	e := &Kevent{
		Kparams:  make(Kparams),
		Metadata: make(map[MetadataKey]any),
	}
	if err := e.UnmarshalRaw(buf, kcapver.KevtSecV1); err != nil {
		return nil, err
	}
	return e, nil
}

// AddMeta appends a key/value pair to event's metadata.
func (e *Kevent) AddMeta(k MetadataKey, v any) {
	e.Metadata[k] = v
}

// AppendParam adds a new parameter to this event.
func (e *Kevent) AppendParam(name string, typ kparams.Type, value kparams.Value, opts ...ParamOption) {
	e.Kparams.Append(name, typ, value, opts...)
}

// AppendEnum adds the enum parameter to this event.
func (e *Kevent) AppendEnum(name string, value uint32, enum ParamEnum) {
	e.AppendParam(name, kparams.Enum, value, WithEnum(enum))
}

// GetParamAsString returns the specified parameter value as string.
// Parameter values are resolved according to their types. For instance,
// if the parameter type is `Status`, the system error code is converted
// to the error message.
// Returns an empty string if the given parameter name is not found
// in event parameters.
func (e Kevent) GetParamAsString(name string) string {
	par, err := e.Kparams.Get(name)
	if err != nil {
		return ""
	}
	return par.String()
}

// GetFlagsAsSlice returns parameter flags as a slice of bitmask string values.
func (e Kevent) GetFlagsAsSlice(name string) []string {
	return strings.Split(e.GetParamAsString(name), "|")
}

// Release returns an event to the pool.
func (e *Kevent) Release() {
	*e = Kevent{} // clear event
	pool.Put(e)
}

// SequenceBy returns the BY statement join field from event metadata.
func (e *Kevent) SequenceBy() any { return e.Metadata[RuleSequenceByKey] }
