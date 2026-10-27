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
	"math"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"github.com/rabbitstack/fibratus/pkg/util/va"

	"github.com/rabbitstack/fibratus/pkg/cap/section"
	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
)

var (
	// SerializeHandles indicates if handles are serialized as part of the process state
	SerializeHandles bool
	// SerializeThreads indicates if threads are serialized as part of the process state
	SerializeThreads bool
	// SerializeModules indicates if modules are serialized as part of the process state
	SerializeModules bool
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
	b = append(b, bytes.WriteUint16(uint16(e.Type))...)
	b = append(b, e.CPU)

	// for the string fields we have to write the length prior to
	// the string buffer itself, so we can decode the string correctly
	// write host name
	b = append(b, bytes.WriteUint16(uint16(len(e.Host)))...)
	b = append(b, e.Host...)

	// write event's timestamp
	timestamp := make([]byte, 0)
	timestamp = e.Timestamp.AppendFormat(timestamp, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(timestamp)))...)
	b = append(b, timestamp...)

	// write the number of event parameters followed by each parameter. Parameters are
	// serialized in schema order, and the ones lacking a value are skipped
	var (
		nparams uint16
		pb      []byte
	)
	for i := range e.Params {
		par := e.Params[i]
		if par.IsNull() {
			continue
		}
		var ok bool
		if pb, ok = appendCaptureParam(pb, par); ok {
			nparams++
		}
	}
	b = append(b, bytes.WriteUint16(nparams)...)
	b = append(b, pb...)

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

// appendCaptureParam serializes the parameter in the capture file format.
// It returns false if the parameter can't be represented in the capture, in
// which case the buffer is returned unchanged.
func appendCaptureParam(b []byte, par Param) ([]byte, bool) {
	typ := par.CaptureType()
	v := par.Value
	name := par.Name()

	// append the type, parameter size and name
	hdr := make([]byte, 0, 4+len(name))
	hdr = append(hdr, bytes.WriteUint16(uint16(typ))...)
	hdr = append(hdr, bytes.WriteUint16(uint16(len(name)))...)
	hdr = append(hdr, name...)

	switch typ {
	case params.String, params.Path:
		var str string
		switch par.Type() {
		case params.Key, params.DOSPath, params.HandleType:
			// store the resolved string, e.g. the DOS path with the
			// drive letter replaced by the mapped device name
			str = par.String()
		default:
			str = v.Str()
		}
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint16(uint16(len(str)))...)
		b = append(b, str...)
	case params.Uint8, params.Int8:
		b = append(b, hdr...)
		b = append(b, byte(v.Uint64()))
	case params.Uint16, params.Port, params.Int16:
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint16(v.Uint16())...)
	case params.Uint32, params.Status, params.Enum, params.Flags32, params.Int32, params.PID, params.TID:
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint32(v.Uint32())...)
	case params.Uint64, params.Address, params.Flags64, params.Int64:
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint64(v.Uint64())...)
	case params.Float:
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint32(math.Float32bits(v.Float32()))...)
	case params.Double:
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint64(math.Float64bits(v.Float64()))...)
	case params.IPv4:
		ip4 := v.IP().To4()
		if ip4 == nil {
			return b, false
		}
		b = append(b, hdr...)
		b = append(b, ip4...)
	case params.IPv6:
		ip6 := v.IP().To16()
		if ip6 == nil {
			return b, false
		}
		b = append(b, hdr...)
		b = append(b, ip6...)
	case params.Bool:
		b = append(b, hdr...)
		b = append(b, convert.Btoi(v.Bool()))
	case params.Time:
		ts := make([]byte, 0, 32)
		ts = v.Time().AppendFormat(ts, time.RFC3339Nano)
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint16(uint16(len(ts)))...)
		b = append(b, ts...)
	case params.Slice:
		switch v.Kind() {
		case params.KindStringSlice:
			slice := v.StrSlice()
			b = append(b, hdr...)
			// append the type for slice elements
			b = append(b, uint8('s'))
			b = append(b, bytes.WriteUint16(uint16(len(slice)))...)
			for _, s := range slice {
				b = append(b, bytes.WriteUint16(uint16(len(s)))...)
				b = append(b, s...)
			}
		case params.KindUintSlice:
			slice := v.U64Slice()
			b = append(b, hdr...)
			// 8 byte integers
			b = append(b, uint8('8'))
			b = append(b, bytes.WriteUint16(uint16(len(slice)))...)
			for _, n := range slice {
				b = append(b, bytes.WriteUint64(n)...)
			}
		default:
			return b, false
		}
	case params.Binary, params.SID, params.WbemSID, params.TokenIntegrityLevel:
		bin := v.Bytes()
		b = append(b, hdr...)
		b = append(b, bytes.WriteUint32(uint32(len(bin)))...)
		b = append(b, bin...)
	default:
		return b, false
	}
	return b, true
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

	// set start index depending
	// on event section version
	var idx uint32
	switch ver {
	case capver.EvtSecV1:
		idx = 33
	case capver.EvtSecV2:
		idx = 34
	case capver.EvtSecV3:
		idx = 18
	}

	e.Type = Type(bytes.ReadUint16(b[16:idx]))
	e.Params = NewParams(e.Type)
	e.CPU = b[idx : idx+1][0]

	idx++ // increment index
	var offset uint32

	// read host name
	l := bytes.ReadUint16(b[inc(idx, 0):])
	buf := b[inc(idx, 2):]
	offset = uint32(l)
	e.Host = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read timestamp
	l = bytes.ReadUint16(b[inc(idx, 2)+offset:])
	buf = b[inc(idx, 4)+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		var err error
		e.Timestamp, err = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		if err != nil {
			unmarshalTimestampErrors.Add(1)
		}
	}

	// read parameters
	nparams := bytes.ReadUint16(b[inc(idx, 4)+offset:])
	// accumulates the offset of all parameter name and value lengths
	var poffset uint32

	for i := 0; i < int(nparams); i++ {
		// read param type
		typ := bytes.ReadUint16(b[inc(idx, 6)+offset+poffset:])
		// read param name
		paramNameLength := uint32(bytes.ReadUint16(b[inc(idx, 8)+offset+poffset:]))
		buf = b[inc(idx, 10)+offset+poffset:]
		paramName := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:paramNameLength:paramNameLength])

		pi := inc(idx, 10) // parameter index

		var val params.Value
		switch params.Type(typ) {
		case params.String, params.Path:
			// read string parameter
			l := bytes.ReadUint16(b[pi+offset+paramNameLength+poffset:])
			buf = b[inc(idx, 12)+offset+paramNameLength+poffset:]
			if len(buf) > 0 {
				val = params.Str(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
			}
			// increment parameter offset by string by type length + name length bytes + length of
			// the string parameter + string parameter size
			poffset += paramNameLength + 6 + uint32(l)
		case params.Uint64, params.Address, params.Flags64:
			val = params.U64(bytes.ReadUint64(b[pi+offset+paramNameLength+poffset:]))
			// increment parameter offset by type length + name length sizes + size of uint64
			poffset += paramNameLength + 4 + 8
		case params.Int64:
			val = params.I64(int64(bytes.ReadUint64(b[pi+offset+paramNameLength+poffset:])))
			// increment parameter offset by type length + name length sizes + size of int64
			poffset += paramNameLength + 4 + 8
		case params.Double:
			val = params.F64(math.Float64frombits(bytes.ReadUint64(b[pi+offset+paramNameLength+poffset:])))
			poffset += paramNameLength + 4 + 8
		case params.Float:
			val = params.F32(math.Float32frombits(bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:])))
			poffset += paramNameLength + 4 + 4
		case params.IPv4:
			val = params.IPv4LE(bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:]))
			// // increment by IPv4 length
			poffset += paramNameLength + 4 + 4
		case params.IPv6:
			val = params.IP6(b[pi+offset+paramNameLength+poffset : pi+offset+paramNameLength+poffset+16])
			// increment by IPv6 length
			poffset += paramNameLength + 4 + 16
		case params.PID, params.TID:
			val = params.U32(bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:]))
			poffset += paramNameLength + 4 + 4
		case params.Int32:
			val = params.I32(int32(bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:])))
			poffset += paramNameLength + 4 + 4
		case params.Uint32, params.Enum, params.Flags32, params.Status:
			val = params.U32(bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:]))
			poffset += paramNameLength + 4 + 4
		case params.Uint16, params.Port:
			val = params.U16(bytes.ReadUint16(b[pi+offset+paramNameLength+poffset:]))
			poffset += paramNameLength + 4 + 2
		case params.Int16:
			val = params.I16(int16(bytes.ReadUint16(b[pi+offset+paramNameLength+poffset:])))
			poffset += paramNameLength + 4 + 2
		case params.Uint8:
			val = params.U8(b[pi+offset+paramNameLength+poffset : pi+offset+paramNameLength+poffset+1][0])
			poffset += paramNameLength + 4 + 1
		case params.Int8:
			val = params.I8(int8(b[pi+offset+paramNameLength+poffset : pi+offset+paramNameLength+poffset+1][0]))
			poffset += paramNameLength + 4 + 1
		case params.Bool:
			v := b[pi+offset+paramNameLength+poffset : pi+offset+paramNameLength+poffset+1][0]
			val = params.Boolean(v == 1)
			poffset += paramNameLength + 4 + 1
		case params.Time:
			// read ts length
			l := bytes.ReadUint16(b[pi+offset+paramNameLength+poffset:])
			buf = b[inc(idx, 12)+offset+paramNameLength+poffset:]
			if len(buf) > 0 {
				t, err := time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
				if err != nil {
					unmarshalTimestampErrors.Add(1)
				} else {
					val = params.Timestamp(t)
				}
			}
			poffset += paramNameLength + 6 + uint32(l)
		case params.Slice:
			// read slice element type
			typ := b[pi+offset+paramNameLength+poffset]
			// read slice size
			l := bytes.ReadUint16(b[inc(idx, 11)+offset+paramNameLength+poffset:])
			var off uint32
			switch typ {
			case 's':
				s := make([]string, l)
				for i := 0; i < int(l); i++ {
					size := bytes.ReadUint16(b[inc(idx, 13)+offset+paramNameLength+poffset+off:])
					if size > 0 {
						buf := b[inc(idx, 15)+offset+paramNameLength+poffset+off:]
						s[i] = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:size:size])
					}
					off += 2 + uint32(size)
				}
				val = params.StrSlice(s)
			case '8':
				v := make([]uint64, l)
				for i := 0; i < int(l); i++ {
					v[i] = bytes.ReadUint64(b[inc(idx, 13)+offset+paramNameLength+poffset+off:])
					off += 8
				}
				val = params.U64Slice(v)
			}
			poffset += paramNameLength + 4 + 1 + 2 + off
		case params.Binary, params.SID, params.WbemSID, params.TokenIntegrityLevel:
			l := bytes.ReadUint32(b[pi+offset+paramNameLength+poffset:])
			buf = b[inc(idx, 12)+offset+paramNameLength+poffset:]
			if len(buf) > 0 {
				// copy the buffer, since it is owned by the capture reader
				bin := make([]byte, l)
				copy(bin, buf[:l])
				val = params.Bin(bin)
			}
			poffset += paramNameLength + 8 + l
		}

		if !val.IsNull() {
			e.Params.setFromCapture(paramName, params.Type(typ), val)
		}
	}

	offset += poffset

	// read metadata tags
	ntags := bytes.ReadUint16(b[inc(idx, 6)+offset:])
	var moffset uint32
	for i := 0; i < int(ntags); i++ {
		// read key
		klen := uint32(bytes.ReadUint16(b[inc(idx, 8)+offset+moffset:]))
		buf = b[inc(idx, 10)+offset+moffset:]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		// read value
		vlen := uint32(bytes.ReadUint16(b[inc(idx, 10)+offset+klen+moffset:]))
		buf = b[inc(idx, 12)+offset+klen+moffset:]
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
	sec := section.Read(b[inc(idx, 8)+offset:])
	if sec.Size() != 0 {
		ps, err := ptypes.NewFromCapture(b[inc(idx, 18)+offset:], sec)
		if err != nil {
			return err
		}
		e.PS = ps
	}

	return nil
}

var js = newJSONStream()

func writePsResources() bool {
	return SerializeHandles || SerializeThreads || SerializeModules || SerializePE
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

	js.writeObjectField("name").writeString(e.Name()).writeMore()
	js.writeObjectField("category").writeString(e.Category().String()).writeMore()
	js.writeObjectField("description").writeString(e.Description()).writeMore()
	js.writeObjectField("host").writeString(e.Host).writeMore()

	timestamp := make([]byte, 0)
	timestamp = e.Timestamp.AppendFormat(timestamp, time.RFC3339Nano)
	js.writeObjectField("timestamp").writeString(string(timestamp)).writeMore()

	// start params
	js.writeObjectField("params")
	js.writeObjectStart()

	idxs := e.Params.sortedPresent(nil)
	for i, idx := range idxs {
		par := e.Params[idx]
		v := par.Value
		writeMore := js.shouldWriteMore(i, len(idxs))
		js.writeObjectField(par.Name())
		switch par.Type() {
		case params.Int64:
			js.writeInt64(v.Int64())
		case params.Uint64:
			js.writeUint64(v.Uint64())
		case params.Int32:
			js.writeInt32(v.Int32())
		case params.Uint32:
			js.writeUint32(v.Uint32())
		case params.Int16:
			js.writeInt16(v.Int16())
		case params.Uint16, params.Port:
			js.writeUint16(v.Uint16())
		case params.Int8:
			js.writeInt8(v.Int8())
		case params.Uint8:
			js.writeUint8(v.Uint8())
		case params.Float:
			js.writeFloat32(v.Float32())
		case params.Double:
			js.writeFloat64(v.Float64())
		case params.PID, params.TID:
			js.writeUint32(v.Uint32())
		case params.IPv4, params.IPv6, params.IP:
			js.writeString(v.IP().String())
		case params.Bool:
			js.writeBool(v.Bool())
		case params.Time:
			js.writeString(v.Time().String())
		case params.Slice, params.Variant:
			switch v.Kind() {
			case params.KindStringSlice:
				slice := v.StrSlice()
				js.writeArrayStart()
				for i, s := range slice {
					writeMore := js.shouldWriteMore(i, len(slice))
					js.writeEscapeString(s)
					if writeMore {
						js.writeMore()
					}
				}
				js.writeArrayEnd()
			case params.KindUintSlice:
				slice := v.U64Slice()
				js.writeArrayStart()
				for i, a := range slice {
					writeMore := js.shouldWriteMore(i, len(slice))
					js.writeString(va.Address(a).String())
					if writeMore {
						js.writeMore()
					}
				}
				js.writeArrayEnd()
			default:
				js.writeEscapeString(par.String())
			}
		default:
			js.writeEscapeString(par.String())
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
			if SerializeModules || SerializeHandles {
				js.writeMore()
			}
		}

		if SerializeModules {
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
