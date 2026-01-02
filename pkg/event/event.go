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

package event

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
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
	// RuleSequenceLink represents the join link values in sequence rules
	RuleSequenceLinks MetadataKey = "rule.seq.links"
	// RuleSequenceOOOKey the presence of this metadata key indicates the
	// event in the partials list arrived out of order and requires reevaluation
	RuleSequenceOOOKey MetadataKey = "rule.seq.ooo"
	// EvasionsKey represents the evasion behaviours detected on the event
	EvasionsKey MetadataKey = "evasions"
)

func (key MetadataKey) String() string { return string(key) }

// String turns event's metadata into string.
func (md Metadata) String() string {
	var sb strings.Builder
	for k, v := range md {
		sb.WriteString(k.String() + ": " + fmt.Sprintf("%v", v) + ", ")
	}
	return strings.TrimSuffix(sb.String(), ", ")
}

// Event encapsulates event's state and provides a set of methods for
// accessing and manipulating event parameters, process state, and other
// metadata. The fields in this structure are organized for cache-optimal
// layout.
type Event struct {
	// Seq is monotonically incremented event sequence.
	Seq uint64 `json:"seq"`
	// Timestamp represents the temporal occurrence of the event.
	Timestamp time.Time `json:"timestamp"`
	// PID is the identifier of the process that generated the event.
	PID uint32 `json:"pid"`
	// Tid is the thread identifier of the thread that generated the event.
	Tid uint32 `json:"tid"`
	// Evasions is the bitmask that stores detected evasion types on this event.
	Evasions uint32 `json:"-"`
	// Type is the internal representation of the event. This field should be
	// ignored by serializers.
	Type Type `json:"-"`
	// CPU designates the processor logical core where the event was originated.
	CPU uint8 `json:"cpu"`
	// WaitEnqueue indicates if this event should temporarily defer pushing to
	// the consumer output queue. This is usually required in event processors
	// to propagate certain events stored in processor's state when the related
	// event arrives.
	WaitEnqueue bool `json:"waitenqueue"`

	// Name is the human friendly name of the event.
	Name string `json:"name"`
	// Category designates the category to which this event pertains.
	Category Category `json:"category"`
	// Description is the short explanation that describes the purpose of the event.
	Description string `json:"description"`
	// Host is the machine name that reported the generated event.
	Host string `json:"host"`
	// Params stores the collection of event parameters.
	Params Params `json:"-"`
	// Metadata represents any tags that are meaningful to this event.
	Metadata Metadata `json:"metadata"`
	// PS represents process' metadata and its allocated resources such as handles, DLLs, etc.
	PS *pstypes.PS `json:"ps,omitempty"`
	// Callstack represents the call stack for the thread that generated the event.
	Callstack callstack.Callstack `json:"callstack"`

	// mmux guards the metadata map
	mmux sync.RWMutex
}

// String returns event's string representation.
func (e *Event) String() string {
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
		Params: %s
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
			e.Params,
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
		Params: %s
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
		e.Params,
		e.Metadata,
	)
}

// StringShort returns event's string representation
// by removing some irrelevant event/process fields.
func (e *Event) StringShort() string {
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
			e.Params,
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
		e.Params,
	)
}

// Empty return a pristine event instance.
func Empty() *Event {
	return &Event{
		Params:   map[string]*Param{},
		Metadata: make(map[MetadataKey]any),
		PS:       &pstypes.PS{},
	}
}

// NewFromCapture recovers the event instance from the capture byte buffer.
func NewFromCapture(buf []byte, ver capver.Version) (*Event, error) {
	e := &Event{
		Params:   make(Params),
		Metadata: make(map[MetadataKey]any),
	}
	if err := e.UnmarshalRaw(buf, ver); err != nil {
		return nil, err
	}
	return e, nil
}

// AddMeta appends a key/value pair to event's metadata.
func (e *Event) AddMeta(k MetadataKey, v any) {
	e.mmux.Lock()
	defer e.mmux.Unlock()
	if e.Metadata == nil {
		e.Metadata = make(map[MetadataKey]any)
	}
	e.Metadata[k] = v
}

// AddOrAppendMetaSlice puts the provided string into the slice if the key
// doesn't exist or appends the string to the slice.
func (e *Event) AddOrAppendMetaSlice(k MetadataKey, s string) {
	if e.ContainsMeta(k) {
		v := append(e.GetMeta(k).([]string), s)
		e.AddMeta(k, v)
	} else {
		e.AddMeta(k, []string{s})
	}
}

// RemoveMeta removes the event metadata index by given key.
func (e *Event) RemoveMeta(k MetadataKey) {
	e.mmux.Lock()
	defer e.mmux.Unlock()
	if e.Metadata != nil {
		delete(e.Metadata, k)
	}
}

// GetMetaAsString returns the metadata as a string value.
func (e *Event) GetMetaAsString(k MetadataKey) string {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	if e.Metadata == nil {
		return ""
	}
	if v, ok := e.Metadata[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetMeta returns the metadata for the given key.
func (e *Event) GetMeta(k MetadataKey) any {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	if e.Metadata == nil {
		return ""
	}
	return e.Metadata[k]
}

// ContainsMeta returns true if the metadata contains the specified key.
func (e *Event) ContainsMeta(k MetadataKey) bool {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	if e.Metadata == nil {
		return false
	}
	return e.Metadata[k] != nil
}

// AddSequenceLink adds a new sequence link to the set.
func (e *Event) AddSequenceLink(link any) {
	if e.ContainsMeta(RuleSequenceLinks) {
		links, ok := e.GetMeta(RuleSequenceLinks).(map[any]struct{})
		if !ok {
			return
		}
		links[link] = struct{}{}
		e.AddMeta(RuleSequenceLinks, links)
	} else {
		e.AddMeta(RuleSequenceLinks, map[any]struct{}{link: {}})
	}
}

// AppendParam adds a new parameter to this event.
func (e *Event) AppendParam(name string, typ params.Type, value params.Value, opts ...ParamOption) {
	e.Params.Append(name, typ, value, opts...)
}

// AppendEnum adds the enum parameter to this event.
func (e *Event) AppendEnum(name string, value uint32, enum ParamEnum) {
	e.AppendParam(name, params.Enum, value, WithEnum(enum))
}

// AppendFlags adds the flags parameter to this event.
func (e *Event) AppendFlags(name string, value uint32, flags ParamFlags) {
	e.AppendParam(name, params.Flags, value, WithFlags(flags))
}

// GetParamAsString returns the specified parameter value as string.
// Parameter values are resolved according to their types. For instance,
// if the parameter type is `Status`, the system error code is converted
// to the error message.
// Returns an empty string if the given parameter name is not found
// in event parameters.
func (e *Event) GetParamAsString(name string) string {
	par, err := e.Params.Get(name)
	if err != nil {
		return ""
	}
	return par.String()
}

// GetFlagsAsSlice returns parameter flags as a slice of bitmask string values.
func (e *Event) GetFlagsAsSlice(name string) []string {
	return strings.Split(e.GetParamAsString(name), "|")
}

// SequenceLink returns the sequence link values from event metadata.
func (e *Event) SequenceLinks() []any {
	e.mmux.RLock()
	defer e.mmux.RUnlock()
	links, ok := e.Metadata[RuleSequenceLinks].(map[any]struct{})
	if !ok {
		return nil
	}
	s := make([]any, 0, len(links))
	for v := range links {
		s = append(s, v)
	}
	return s
}
