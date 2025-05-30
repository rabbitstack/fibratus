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

package event

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"math"
	"net"
	"sort"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/cap/section"
	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
)

var (
	// SerializeHandles indicates if handles are serialized as part of the process state
	SerializeHandles bool
	// SerializeThreads indicates if threads are serialized as part of the process state
	SerializeThreads bool
	// SerializeImages indicates if images are serialized as part of the process state
	SerializeImages bool
	// SerializePE indicates if PE metadata are serialized as part of the process state
	SerializePE bool
	// SerializeEnvs indicates if the environment variables are serialized as part of the process state
	SerializeEnvs bool
)

// unmarshalTimestampErrors counts timestamp unmarshal errors
var unmarshalTimestampErrors = expvar.NewInt("event.timestamp.unmarshal.errors")

// MarshalRaw produces a byte stream of the kernel event suitable for writing to disk.
func (e *Event) MarshalRaw() []byte {
	b := make([]byte, 0)

	// write seq, pid, tid fields
	b = append(b, bytes.WriteUint64(e.Seq)...)
	b = append(b, bytes.WriteUint32(e.PID)...)
	b = append(b, bytes.WriteUint32(e.Tid)...)

	// write type and CPU
	b = append(b, e.Type[:]...)
	b = append(b, e.CPU)

	// for the string fields we have to write the length prior to
	// the string buffer itself, so we can decode the string correctly
	//
	// write event name
	b = append(b, bytes.WriteUint16(uint16(len(e.Name)))...)
	b = append(b, e.Name...)
	// write category
	b = append(b, bytes.WriteUint16(uint16(len(e.Category)))...)
	b = append(b, e.Category...)
	// write description
	b = append(b, bytes.WriteUint16(uint16(len(e.Description)))...)
	b = append(b, e.Description...)
	// write host name
	b = append(b, bytes.WriteUint16(uint16(len(e.Host)))...)
	b = append(b, e.Host...)

	// write event's timestamp
	timestamp := make([]byte, 0)
	timestamp = e.Timestamp.AppendFormat(timestamp, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(timestamp)))...)
	b = append(b, timestamp...)

	// write the number of event parameters followed by each parameter
	b = append(b, bytes.WriteUint16(uint16(len(e.Params)))...)
	for _, par := range e.Params {
		// append the type, parameter size and name
		b = append(b, bytes.WriteUint16(uint16(par.CaptureType()))...)
		b = append(b, bytes.WriteUint16(uint16(len(par.Name)))...)
		b = append(b, par.Name...)
		switch par.Type {
		case params.AnsiString, params.UnicodeString:
			b = append(b, bytes.WriteUint16(uint16(len(par.Value.(string))))...)
			b = append(b, par.Value.(string)...)
		case params.Key, params.Path, params.DOSPath, params.HandleType:
			v := e.GetParamAsString(par.Name)
			b = append(b, bytes.WriteUint16(uint16(len(v)))...)
			b = append(b, v...)
		case params.Uint8:
			b = append(b, par.Value.(uint8))
		case params.Int8:
			b = append(b, byte(par.Value.(int8)))
		case params.Uint16, params.Port:
			b = append(b, bytes.WriteUint16(par.Value.(uint16))...)
		case params.Int16:
			b = append(b, bytes.WriteUint16(uint16(par.Value.(int16)))...)
		case params.Uint32, params.Status, params.Enum, params.Flags:
			b = append(b, bytes.WriteUint32(par.Value.(uint32))...)
		case params.Int32:
			b = append(b, bytes.WriteUint32(uint32(par.Value.(int32)))...)
		case params.Uint64, params.Address, params.Flags64:
			b = append(b, bytes.WriteUint64(par.Value.(uint64))...)
		case params.Int64:
			b = append(b, bytes.WriteUint64(uint64(par.Value.(int64)))...)
		case params.Double:
			b = append(b, bytes.WriteUint32(math.Float32bits(par.Value.(float32)))...)
		case params.Float:
			b = append(b, bytes.WriteUint64(math.Float64bits(par.Value.(float64)))...)
		case params.IPv4:
			b = append(b, par.Value.(net.IP).To4()...)
		case params.IPv6:
			b = append(b, par.Value.(net.IP).To16()...)
		case params.PID, params.TID:
			b = append(b, bytes.WriteUint32(par.Value.(uint32))...)
		case params.Bool:
			b = append(b, convert.Btoi(par.Value.(bool)))
		case params.Time:
			v := par.Value.(time.Time)
			ts := make([]byte, 0)
			ts = v.AppendFormat(ts, time.RFC3339Nano)
			b = append(b, bytes.WriteUint16(uint16(len(ts)))...)
			b = append(b, ts...)
		case params.Slice:
			switch slice := par.Value.(type) {
			case []string:
				// append the type for slice elements
				b = append(b, uint8('s'))
				b = append(b, bytes.WriteUint16(uint16(len(slice)))...)
				for _, s := range slice {
					b = append(b, bytes.WriteUint16(uint16(len(s)))...)
					b = append(b, s...)
				}
			case []va.Address:
				// 8 byte integers
				b = append(b, uint8('8'))
				b = append(b, bytes.WriteUint16(uint16(len(slice)))...)
				for _, v := range slice {
					b = append(b, bytes.WriteUint64(v.Uint64())...)
				}
			}
		case params.Binary, params.SID, params.WbemSID:
			b = append(b, bytes.WriteUint32(uint32(len(par.Value.([]byte))))...)
			b = append(b, par.Value.([]byte)...)
		}
	}

	// write metadata key/value pairs
	b = append(b, bytes.WriteUint16(uint16(len(e.Metadata)))...)
	for key, value := range e.Metadata {
		b = append(b, bytes.WriteUint16(uint16(len(key)))...)
		b = append(b, key...)
		v := fmt.Sprintf("%s", value)
		b = append(b, bytes.WriteUint16(uint16(len(v)))...)
		b = append(b, v...)
	}

	// write process state
	if e.PS != nil && (e.IsCreateProcess() || e.IsProcessRundown()) {
		buf := e.PS.Marshal()
		sec := section.New(section.Process, capver.ProcessSecV4, 0, uint32(len(buf)))
		b = append(b, sec[:]...)
		b = append(b, buf...)
	} else {
		sec := section.New(section.Process, capver.ProcessSecV4, 0, 0)
		b = append(b, sec[:]...)
	}

	return b
}

func inc(idx, inc uint32) uint32 {
	return idx + inc
}

// UnmarshalRaw recovers the state of the kernel event from the byte stream.
func (e *Event) UnmarshalRaw(b []byte, ver capver.Version) error {
	if len(b) < 34 {
		return fmt.Errorf("expected at least 34 bytes but got %d bytes", len(b))
	}

	// read seq, pid, tid
	e.Seq = bytes.ReadUint64(b[0:])
	e.PID = bytes.ReadUint32(b[8:])
	e.Tid = bytes.ReadUint32(b[12:])

	// read type and CPU
	var typ Type
	// set start index depending
	// on event section version
	var idx uint32
	switch ver {
	case capver.EvtSecV1:
		idx = 33
	case capver.EvtSecV2:
		idx = 34
	}
	copy(typ[:], b[16:idx])
	e.Type = typ
	e.CPU = b[idx : idx+1][0]

	idx++ // increment index
	var offset uint32

	// read event name
	l := bytes.ReadUint16(b[inc(idx, 0):])
	buf := b[inc(idx, 2):]
	offset = uint32(l)
	e.Name = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read category
	l = bytes.ReadUint16(b[inc(idx, 2)+offset:])
	buf = b[inc(idx, 4)+offset:]
	offset += uint32(l)
	e.Category = Category(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read description
	l = bytes.ReadUint16(b[inc(idx, 4)+offset:])
	buf = b[inc(idx, 6)+offset:]
	offset += uint32(l)
	e.Description = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read host name
	l = bytes.ReadUint16(b[inc(idx, 6)+offset:])
	buf = b[inc(idx, 8)+offset:]
	offset += uint32(l)
	e.Host = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read timestamp
	l = bytes.ReadUint16(b[inc(idx, 8)+offset:])
	buf = b[inc(idx, 10)+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		var err error
		e.Timestamp, err = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		if err != nil {
			unmarshalTimestampErrors.Add(1)
		}
	}

	// read parameters
	nparams := bytes.ReadUint16(b[inc(idx, 10)+offset:])
	// accumulates the offset of all parameter name and value lengths
	var poffset uint32

	for i := 0; i < int(nparams); i++ {
		// read Param type
		typ := bytes.ReadUint16(b[inc(idx, 12)+offset+poffset:])
		// read Param name
		kparamNameLength := uint32(bytes.ReadUint16(b[inc(idx, 14)+offset+poffset:]))
		buf = b[inc(idx, 16)+offset+poffset:]
		kparamName := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:kparamNameLength:kparamNameLength])

		pi := inc(idx, 16) // parameter index

		var val params.Value
		switch params.Type(typ) {
		case params.AnsiString, params.UnicodeString, params.Path:
			// read string parameter
			l := bytes.ReadUint16(b[pi+offset+kparamNameLength+poffset:])
			buf = b[inc(idx, 18)+offset+kparamNameLength+poffset:]
			if len(buf) > 0 {
				val = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
			}
			// increment parameter offset by string by type length + name length bytes + length of
			// the string parameter + string parameter size
			poffset += kparamNameLength + 6 + uint32(l)
		case params.Uint64, params.Address, params.Flags64:
			val = bytes.ReadUint64(b[pi+offset+kparamNameLength+poffset:])
			// increment parameter offset by type length + name length sizes + size of uint64
			poffset += kparamNameLength + 4 + 8
		case params.Int64:
			val = int64(bytes.ReadUint64(b[pi+offset+kparamNameLength+poffset:]))
			// increment parameter offset by type length + name length sizes + size of int64
			poffset += kparamNameLength + 4 + 8
		case params.Double:
			val = float64(bytes.ReadUint64(b[pi+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 8
		case params.Float:
			val = float32(bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 4
		case params.IPv4:
			val = ip.ToIPv4(bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:]))
			// // increment by IPv4 length
			poffset += kparamNameLength + 4 + 4
		case params.IPv6:
			val = ip.ToIPv6(b[pi+offset+kparamNameLength+poffset : pi+offset+kparamNameLength+poffset+16])
			// increment by IPv6 length
			poffset += kparamNameLength + 4 + 16
		case params.PID, params.TID:
			val = bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 4
		case params.Int32:
			val = int32(bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 4
		case params.Uint32, params.Enum, params.Flags, params.Status:
			val = bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 4
		case params.Uint16, params.Port:
			val = bytes.ReadUint16(b[pi+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 2
		case params.Int16:
			val = int16(bytes.ReadUint16(b[pi+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 2
		case params.Uint8:
			val = b[pi+offset+kparamNameLength+poffset : pi+offset+kparamNameLength+poffset+1][0]
			poffset += kparamNameLength + 4 + 1
		case params.Int8:
			val = int8(b[pi+offset+kparamNameLength+poffset : pi+offset+kparamNameLength+poffset+1][0])
			poffset += kparamNameLength + 4 + 1
		case params.Bool:
			v := b[pi+offset+kparamNameLength+poffset : pi+offset+kparamNameLength+poffset+1][0]
			if v == 1 {
				val = true
			} else {
				val = false
			}
			poffset += kparamNameLength + 4 + 1
		case params.Time:
			// read ts length
			l := bytes.ReadUint16(b[pi+offset+kparamNameLength+poffset:])
			buf = b[inc(idx, 18)+offset+kparamNameLength+poffset:]
			if len(buf) > 0 {
				var err error
				val, err = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
				if err != nil {
					unmarshalTimestampErrors.Add(1)
				}
			}
			poffset += kparamNameLength + 6 + uint32(l)
		case params.Slice:
			// read slice element type
			typ := b[pi+offset+kparamNameLength+poffset]
			// read slice size
			l := bytes.ReadUint16(b[inc(idx, 17)+offset+kparamNameLength+poffset:])
			var off uint32
			switch typ {
			case 's':
				s := make([]string, l)
				for i := 0; i < int(l); i++ {
					size := bytes.ReadUint16(b[inc(idx, 19)+offset+kparamNameLength+poffset+off:])
					buf := b[inc(idx, 22)+offset+kparamNameLength+poffset+off:]
					s[i] = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:size:size])
					off += 2 + uint32(size)
				}
				val = s
			case '8':
				v := make([]uint64, l)
				for i := 0; i < int(l); i++ {
					bytes.ReadUint64(b[inc(idx, 22)+offset+kparamNameLength+poffset+off:])
					off += 8
				}
				val = v
			}
			poffset += kparamNameLength + 4 + 1 + 2 + off
		case params.Binary, params.SID, params.WbemSID:
			l := bytes.ReadUint32(b[pi+offset+kparamNameLength+poffset:])
			buf = b[inc(idx, 18)+offset+kparamNameLength+poffset:]
			if len(buf) > 0 {
				val = buf[:l]
			}
			poffset += kparamNameLength + 8 + l
		}

		if val != nil {
			e.Params.AppendFromCapture(kparamName, params.Type(typ), val, e.Type)
		}
	}

	offset += poffset

	// read metadata tags
	ntags := bytes.ReadUint16(b[inc(idx, 12)+offset:])
	var moffset uint32
	for i := 0; i < int(ntags); i++ {
		// read key
		klen := uint32(bytes.ReadUint16(b[inc(idx, 14)+offset+moffset:]))
		buf = b[inc(idx, 16)+offset+moffset:]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		// read value
		vlen := uint32(bytes.ReadUint16(b[inc(idx, 16)+offset+klen+moffset:]))
		buf = b[inc(idx, 18)+offset+klen+moffset:]
		value := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:vlen:vlen])
		// increment the offset by the length of the key + length value + size of uint16 * 2
		// that corresponds to bytes storing the lengths of keys/values
		moffset += klen + vlen + 4
		if key != "" {
			e.AddMeta(MetadataKey(key), value)
		}
	}

	offset += moffset

	// read process state
	sec := section.Read(b[inc(idx, 14)+offset:])
	if sec.Size() != 0 {
		ps, err := ptypes.NewFromCapture(b[inc(idx, 24)+offset:], sec)
		if err != nil {
			return err
		}
		e.PS = ps
	}

	return nil
}

var js = newJSONStream()

func writePsResources() bool {
	return SerializeHandles || SerializeThreads || SerializeImages || SerializePE
}

// MarshalJSON produces a JSON payload for this event.
func (e *Event) MarshalJSON() []byte {
	if e == nil {
		return []byte{}
	}

	// start of JSON
	js.writeObjectStart()

	js.writeObjectField("seq").writeUint64(e.Seq).writeMore()
	js.writeObjectField("pid").writeUint32(e.PID).writeMore()
	js.writeObjectField("tid").writeUint32(e.Tid).writeMore()
	js.writeObjectField("cpu").writeUint8(e.CPU).writeMore()

	js.writeObjectField("name").writeString(e.Name).writeMore()
	js.writeObjectField("category").writeString(string(e.Category)).writeMore()
	js.writeObjectField("description").writeString(e.Description).writeMore()
	js.writeObjectField("host").writeString(e.Host).writeMore()

	timestamp := make([]byte, 0)
	timestamp = e.Timestamp.AppendFormat(timestamp, time.RFC3339Nano)
	js.writeObjectField("timestamp").writeString(string(timestamp)).writeMore()

	// start params
	js.writeObjectField("params")
	js.writeObjectStart()

	pars := make([]*Param, 0, len(e.Params))
	for _, par := range e.Params {
		pars = append(pars, par)
	}
	sort.Slice(pars, func(i, j int) bool { return pars[i].Name < pars[j].Name })

	for i, par := range pars {
		writeMore := js.shouldWriteMore(i, len(pars))
		js.writeObjectField(par.Name)
		switch par.Type {
		case params.Int64:
			js.writeInt64(par.Value.(int64))
		case params.Uint64:
			js.writeUint64(par.Value.(uint64))
		case params.Int32:
			js.writeInt32(par.Value.(int32))
		case params.Uint32:
			js.writeUint32(par.Value.(uint32))
		case params.Int16:
			js.writeInt16(par.Value.(int16))
		case params.Uint16, params.Port:
			js.writeUint16(par.Value.(uint16))
		case params.Int8:
			js.writeInt8(par.Value.(int8))
		case params.Uint8:
			js.writeUint8(par.Value.(uint8))
		case params.Float:
			js.writeFloat32(par.Value.(float32))
		case params.Double:
			js.writeFloat64(par.Value.(float64))
		case params.PID, params.TID:
			js.writeUint32(par.Value.(uint32))
		case params.IPv4, params.IPv6:
			js.writeString(par.Value.(net.IP).String())
		case params.Bool:
			js.writeBool(par.Value.(bool))
		case params.Time:
			js.writeString(par.Value.(time.Time).String())
		case params.Slice:
			switch slice := par.Value.(type) {
			case []string:
				js.writeArrayStart()
				for i, s := range slice {
					writeMore := js.shouldWriteMore(i, len(slice))
					js.writeEscapeString(s)
					if writeMore {
						js.writeMore()
					}
				}
				js.writeArrayEnd()
			}
		default:
			js.writeEscapeString(e.GetParamAsString(par.Name))
		}
		if writeMore {
			js.writeMore()
		}
	}
	// end params
	js.writeObjectEnd().writeMore()

	// start metadata
	js.writeObjectField("meta")
	js.writeObjectStart()
	var i int
	for k, v := range e.Metadata {
		writeMore := js.shouldWriteMore(i, len(e.Metadata))
		js.writeObjectField(k.String()).writeEscapeString(fmt.Sprintf("%s", v))
		if writeMore {
			js.writeMore()
		}
		i++
	}

	// end metadata
	js.writeObjectEnd()
	ps := e.PS
	if ps != nil {
		js.writeMore()
	}

	// start process state
	if ps != nil {
		js.writeObjectField("ps")
		js.writeObjectStart()

		js.writeObjectField("pid").writeUint32(ps.PID).writeMore()
		js.writeObjectField("ppid").writeUint32(ps.Ppid).writeMore()
		js.writeObjectField("name").writeString(ps.Name).writeMore()
		js.writeObjectField("cmdline").writeEscapeString(ps.Cmdline).writeMore()
		js.writeObjectField("exe").writeEscapeString(ps.Exe).writeMore()
		js.writeObjectField("cwd").writeEscapeString(ps.Cwd).writeMore()
		js.writeObjectField("sid").writeEscapeString(ps.SID).writeMore()

		js.writeObjectField("args")
		js.writeArrayStart()
		for i, arg := range ps.Args {
			writeMore := js.shouldWriteMore(i, len(ps.Args))
			js.writeEscapeString(arg)
			if writeMore {
				js.writeMore()
			}
		}
		js.writeArrayEnd().writeMore()

		js.writeObjectField("sessionid").writeUint32(ps.SessionID)

		parent := ps.Parent
		if parent != nil {
			js.writeMore()
			js.writeObjectField("parent")
			js.writeObjectStart()

			js.writeObjectField("name").writeString(parent.Name).writeMore()
			js.writeObjectField("cmdline").writeEscapeString(parent.Cmdline).writeMore()
			js.writeObjectField("exe").writeEscapeString(parent.Exe).writeMore()
			js.writeObjectField("cwd").writeEscapeString(parent.Cwd).writeMore()
			js.writeObjectField("sid").writeEscapeString(parent.SID)

			js.writeObjectEnd()
		}

		if SerializeEnvs {
			js.writeMore()
			js.writeObjectField("envs")
			js.writeObjectStart()
			var i int
			for k, v := range ps.Envs {
				writeMore := js.shouldWriteMore(i, len(ps.Envs))
				js.writeObjectField(k).writeEscapeString(v)
				if writeMore {
					js.writeMore()
				}
				i++
			}
			js.writeObjectEnd()
		}

		if writePsResources() {
			js.writeMore()
		}

		if SerializeThreads {
			// start threads
			js.writeObjectField("threads")
			js.writeArrayStart()
			var i int
			ps.RLock()
			for _, thread := range ps.Threads {
				writeMore := js.shouldWriteMore(i, len(ps.Threads))
				js.writeObjectStart()
				js.writeObjectField("tid").writeUint32(thread.Tid).writeMore()
				js.writeObjectField("ioprio").writeUint8(thread.IOPrio).writeMore()
				js.writeObjectField("baseprio").writeUint8(thread.BasePrio).writeMore()
				js.writeObjectField("pageprio").writeUint8(thread.PagePrio).writeMore()
				js.writeObjectField("start_address").writeString(thread.StartAddress.String()).writeMore()
				js.writeObjectField("ustack_base").writeString(thread.UstackBase.String()).writeMore()
				js.writeObjectField("ustack_limit").writeString(thread.UstackLimit.String()).writeMore()
				js.writeObjectField("kstack_base").writeString(thread.KstackBase.String()).writeMore()
				js.writeObjectField("kstack_limit").writeString(thread.KstackLimit.String())
				js.writeObjectEnd()
				if writeMore {
					js.writeMore()
				}
				i++
			}
			ps.RUnlock()
			// end threads
			js.writeArrayEnd()
			if SerializeImages || SerializeHandles {
				js.writeMore()
			}
		}

		if SerializeImages {
			// start modules
			js.writeObjectField("modules")
			js.writeArrayStart()

			for i, m := range ps.Modules {
				writeMore := js.shouldWriteMore(i, len(ps.Modules))
				js.writeObjectStart()
				js.writeObjectField("name").writeEscapeString(m.Name).writeMore()
				js.writeObjectField("size").writeUint64(m.Size)
				js.writeObjectEnd()
				if writeMore {
					js.writeMore()
				}
			}

			// end modules
			js.writeArrayEnd()
			if SerializeHandles {
				js.writeMore()
			}
		}

		if SerializeHandles {
			// start handles
			js.writeObjectField("handles")
			js.writeArrayStart()

			for i, handle := range ps.Handles {
				writeMore := js.shouldWriteMore(i, len(ps.Handles))
				js.writeObjectStart()
				js.writeObjectField("name").writeEscapeString(handle.Name).writeMore()
				js.writeObjectField("type").writeString(handle.Type).writeMore()
				js.writeObjectField("id").writeUint64(uint64(handle.Num)).writeMore()
				js.writeObjectField("object").writeEscapeString(va.Address(handle.Object).String())
				js.writeObjectEnd()

				if writeMore {
					js.writeMore()
				}
			}
			// end handles
			js.writeArrayEnd()
			if SerializePE && ps.PE != nil {
				js.writeMore()
			}
		}

		pe := ps.PE
		if SerializePE && pe != nil {
			// start PE
			js.writeObjectField("pe")
			js.writeObjectStart()

			js.writeObjectField("nsections").writeUint16(pe.NumberOfSections).writeMore()
			js.writeObjectField("nsymbols").writeUint32(pe.NumberOfSymbols).writeMore()
			js.writeObjectField("image_base").writeString(pe.ImageBase).writeMore()
			js.writeObjectField("entrypoint").writeString(pe.EntryPoint).writeMore()

			timestamp := make([]byte, 0)
			timestamp = e.Timestamp.AppendFormat(timestamp, time.RFC3339Nano)
			js.writeObjectField("link_time").writeString(string(timestamp)).writeMore()

			// sections
			if len(pe.Sections) > 0 {
				js.writeObjectField("sections")
				js.writeArrayStart()

				for i, sec := range pe.Sections {
					writeMore := js.shouldWriteMore(i, len(pe.Sections))
					js.writeObjectStart()
					js.writeObjectField("name").writeEscapeString(sec.Name).writeMore()
					js.writeObjectField("size").writeUint32(sec.Size).writeMore()
					js.writeObjectField("entropy").writeFloat64(sec.Entropy).writeMore()
					js.writeObjectField("md5").writeString(sec.Md5)

					js.writeObjectEnd()
					if writeMore {
						js.writeMore()
					}
				}

				js.writeArrayEnd()
				if len(pe.Symbols) > 0 {
					js.writeMore()
				}
			}

			// imported symbols
			if len(pe.Symbols) > 0 {
				js.writeObjectField("symbols")
				js.writeArrayStart()

				for i, sym := range pe.Symbols {
					writeMore := js.shouldWriteMore(i, len(pe.Symbols))
					js.writeEscapeString(sym)

					if writeMore {
						js.writeMore()
					}
				}

				js.writeArrayEnd()
				if len(pe.Imports) > 0 {
					js.writeMore()
				}
			}

			// imports
			if len(pe.Imports) > 0 {
				js.writeObjectField("imports")
				js.writeArrayStart()

				for i, imp := range pe.Imports {
					writeMore := js.shouldWriteMore(i, len(pe.Imports))
					js.writeEscapeString(imp)

					if writeMore {
						js.writeMore()
					}
				}

				js.writeArrayEnd()
				if len(pe.VersionResources) > 0 {
					js.writeMore()
				}
			}

			// version resources
			if len(pe.VersionResources) > 0 {
				js.writeObjectField("resources")
				js.writeObjectStart()

				var i int
				for k, v := range pe.VersionResources {
					writeMore := js.shouldWriteMore(i, len(pe.VersionResources))
					js.writeObjectField(k).writeEscapeString(v)

					if writeMore {
						js.writeMore()
					}
					i++
				}
				js.writeObjectEnd()
			}

			// end PE
			js.writeObjectEnd()
		}

		// end process state
		js.writeObjectEnd()
	}

	// end of JSON
	js.writeObjectEnd()

	return js.flush()
}
