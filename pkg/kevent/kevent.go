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
	"github.com/rabbitstack/fibratus/pkg/callstack"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"strings"
	"sync"
	"time"
)

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
	// RuleSequenceLink represents the join link value in sequence rules
	RuleSequenceLink MetadataKey = "rule.seq.link"
	// RuleSequenceOOOKey the presence of this metadata key indicates the
	// event in the partials list arrived out of order and requires reevaluation
	RuleSequenceOOOKey MetadataKey = "rule.seq.ooo"
)

func (key MetadataKey) String() string { return string(key) }

// String turns kernel event's metadata into string.
func (md Metadata) String() string {
	var sb strings.Builder
	for k, v := range md {
		sb.WriteString(k.String() + ": " + fmt.Sprintf("%v", v) + ", ")
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
	// mmux guards the metadata map
	mmux sync.RWMutex
	// PS represents process' metadata and its allocated resources such as handles, DLLs, etc.
	PS *pstypes.PS `json:"ps,omitempty"`
	// Callstack represents the call stack for the thread that generated the event.
	Callstack callstack.Callstack `json:"callstack"`
	// WaitEnqueue indicates if this event should temporarily defer pushing to
	// the consumer output queue. This is usually required in event processors
	// to propagate certain events stored in processor's state when the related
	// event arrives.
	WaitEnqueue bool `json:"waitenqueue"`
}

// String returns event's string representation.
func (e *Kevent) String() string {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
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
		Host: %s
		Timestamp: %s
		Kparams: %s
		Metadata: %s
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
		Host: %s
		Timestamp: %s
		Kparams: %s
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

// StringShort returns event's string representation
// by removing some irrelevant event/process fields.
func (e *Kevent) StringShort() string {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	if e.PS != nil {
		return fmt.Sprintf(`
		Seq: %d
		Pid: %d
		Tid: %d
		Name: %s
		Category: %s
		Host: %s
		Timestamp: %s
		Parameters: %s
    %s
	`,
			e.Seq,
			e.PID,
			e.Tid,
			e.Name,
			e.Category,
			e.Host,
			e.Timestamp,
			e.Kparams,
			e.PS.StringShort(),
		)
	}
	return fmt.Sprintf(`
		Seq: %d
		Pid: %d
		Tid: %d
		Name: %s
		Category: %s
		Host: %s
		Timestamp: %s
		Parameters: %s
	`,
		e.Seq,
		e.PID,
		e.Tid,
		e.Name,
		e.Category,
		e.Host,
		e.Timestamp,
		e.Kparams,
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
func NewFromKcap(buf []byte, ver kcapver.Version) (*Kevent, error) {
	e := &Kevent{
		Kparams:  make(Kparams),
		Metadata: make(map[MetadataKey]any),
	}
	if err := e.UnmarshalRaw(buf, ver); err != nil {
		return nil, err
	}
	return e, nil
}

// AddMeta appends a key/value pair to event's metadata.
func (e *Kevent) AddMeta(k MetadataKey, v any) {
	e.mmux.Lock()
	defer e.mmux.Unlock()
	e.Metadata[k] = v
}

// RemoveMeta removes the event metadata index by given key.
func (e *Kevent) RemoveMeta(k MetadataKey) {
	e.mmux.Lock()
	defer e.mmux.Unlock()
	delete(e.Metadata, k)
}

// GetMetaAsString returns the metadata as a string value.
func (e *Kevent) GetMetaAsString(k MetadataKey) string {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	if v, ok := e.Metadata[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ContainsMeta returns true if the metadata contains the specified key.
func (e *Kevent) ContainsMeta(k MetadataKey) bool {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	return e.Metadata[k] != nil
}

// AppendParam adds a new parameter to this event.
func (e *Kevent) AppendParam(name string, typ kparams.Type, value kparams.Value, opts ...ParamOption) {
	e.Kparams.Append(name, typ, value, opts...)
}

// AppendEnum adds the enum parameter to this event.
func (e *Kevent) AppendEnum(name string, value uint32, enum ParamEnum) {
	e.AppendParam(name, kparams.Enum, value, WithEnum(enum))
}

// AppendFlags adds the flags parameter to this event.
func (e *Kevent) AppendFlags(name string, value uint32, flags ParamFlags) {
	e.AppendParam(name, kparams.Flags, value, WithFlags(flags))
}

// GetParamAsString returns the specified parameter value as string.
// Parameter values are resolved according to their types. For instance,
// if the parameter type is `Status`, the system error code is converted
// to the error message.
// Returns an empty string if the given parameter name is not found
// in event parameters.
func (e *Kevent) GetParamAsString(name string) string {
	par, err := e.Kparams.Get(name)
	if err != nil {
		return ""
	}
	return par.String()
}

// GetFlagsAsSlice returns parameter flags as a slice of bitmask string values.
func (e *Kevent) GetFlagsAsSlice(name string) []string {
	return strings.Split(e.GetParamAsString(name), "|")
}

// SequenceLink returns the sequence link value from event metadata.
func (e *Kevent) SequenceLink() any {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	return e.Metadata[RuleSequenceLink]
}
