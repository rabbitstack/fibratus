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

package kevent

import (
	"expvar"
	"fmt"
	"math"
	"net"
	"sort"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	ptypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
)

var (
	// SerializeHandles indicates if handles are serialized as part of the process' state
	SerializeHandles bool
	// SerializeThreads indicates if threads are serialized as part of the process' state
	SerializeThreads bool
	// SerializeImages indicates if images are serialized as part of the process' state
	SerializeImages bool
	// SerializePE indicates if PE metadata are serialized as part of the process' state
	SerializePE bool
	// SerializeEnvs indicates if the environment variables are serialized as part of the process's state
	SerializeEnvs bool
)

// unmarshalTimestampErrors counts timestamp unmarshal errors
var unmarshalTimestampErrors = expvar.NewInt("kevent.timestamp.unmarshal.errors")

// MarshalRaw produces a byte stream of the kernel event suitable for writing to disk.
func (e *Kevent) MarshalRaw() []byte {
	b := make([]byte, 0)

	// write seq, pid, tid fields
	b = append(b, bytes.WriteUint64(e.Seq)...)
	b = append(b, bytes.WriteUint32(e.PID)...)
	b = append(b, bytes.WriteUint32(e.Tid)...)

	// write ktype and CPU
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
	b = append(b, bytes.WriteUint16(uint16(len(e.Kparams)))...)
	for _, kpar := range e.Kparams {
		// append the type, parameter size and name
		b = append(b, bytes.WriteUint16(uint16(kpar.KcapType()))...)
		b = append(b, bytes.WriteUint16(uint16(len(kpar.Name)))...)
		b = append(b, kpar.Name...)
		switch kpar.Type {
		case kparams.AnsiString, kparams.UnicodeString:
			b = append(b, bytes.WriteUint16(uint16(len(kpar.Value.(string))))...)
			b = append(b, kpar.Value.(string)...)
		case kparams.Key, kparams.FilePath, kparams.FileDosPath, kparams.HandleType:
			v := e.GetParamAsString(kpar.Name)
			b = append(b, bytes.WriteUint16(uint16(len(v)))...)
			b = append(b, v...)
		case kparams.SID, kparams.WbemSID:
			sid := e.Kparams.MustGetSID().String()
			b = append(b, bytes.WriteUint16(uint16(len(sid)))...)
			b = append(b, sid...)
		case kparams.Uint8:
			b = append(b, kpar.Value.(uint8))
		case kparams.Int8:
			b = append(b, byte(kpar.Value.(int8)))
		case kparams.HexInt8:
			b = append(b, kpar.Value.(kparams.Hex).Uint8())
		case kparams.HexInt16:
			b = append(b, bytes.WriteUint16(kpar.Value.(kparams.Hex).Uint16())...)
		case kparams.HexInt32:
			b = append(b, bytes.WriteUint32(kpar.Value.(kparams.Hex).Uint32())...)
		case kparams.HexInt64:
			b = append(b, bytes.WriteUint64(kpar.Value.(kparams.Hex).Uint64())...)
		case kparams.Uint16, kparams.Port:
			b = append(b, bytes.WriteUint16(kpar.Value.(uint16))...)
		case kparams.Int16:
			b = append(b, bytes.WriteUint16(uint16(kpar.Value.(int16)))...)
		case kparams.Uint32, kparams.Status, kparams.Enum, kparams.Flags:
			b = append(b, bytes.WriteUint32(kpar.Value.(uint32))...)
		case kparams.Int32:
			b = append(b, bytes.WriteUint32(uint32(kpar.Value.(int32)))...)
		case kparams.Uint64:
			b = append(b, bytes.WriteUint64(kpar.Value.(uint64))...)
		case kparams.Int64:
			b = append(b, bytes.WriteUint64(uint64(kpar.Value.(int64)))...)
		case kparams.Double:
			b = append(b, bytes.WriteUint32(math.Float32bits(kpar.Value.(float32)))...)
		case kparams.Float:
			b = append(b, bytes.WriteUint64(math.Float64bits(kpar.Value.(float64)))...)
		case kparams.IPv4:
			b = append(b, kpar.Value.(net.IP).To4()...)
		case kparams.IPv6:
			b = append(b, kpar.Value.(net.IP).To16()...)
		case kparams.PID, kparams.TID:
			b = append(b, bytes.WriteUint32(kpar.Value.(uint32))...)
		case kparams.Bool:
			v := kpar.Value.(bool)
			if v {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case kparams.Time:
			v := kpar.Value.(time.Time)
			ts := make([]byte, 0)
			ts = v.AppendFormat(ts, time.RFC3339Nano)
			b = append(b, bytes.WriteUint16(uint16(len(ts)))...)
			b = append(b, ts...)
		case kparams.Slice:
			switch slice := kpar.Value.(type) {
			case []string:
				// append the type for slice elements
				b = append(b, uint8('s'))
				b = append(b, bytes.WriteUint16(uint16(len(slice)))...)
				for _, s := range slice {
					b = append(b, bytes.WriteUint16(uint16(len(s)))...)
					b = append(b, s...)
				}
			}
		case kparams.Binary:
			b = append(b, bytes.WriteUint16(uint16(len(kpar.Value.([]byte))))...)
			b = append(b, kpar.Value.([]byte)...)
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
		sec := section.New(section.Process, kcapver.ProcessSecV3, 0, uint32(len(buf)))
		b = append(b, sec[:]...)
		b = append(b, buf...)
	} else {
		sec := section.New(section.Process, kcapver.ProcessSecV3, 0, 0)
		b = append(b, sec[:]...)
	}

	return b
}

// UnmarshalRaw recovers the state of the kernel event from the byte stream.
func (e *Kevent) UnmarshalRaw(b []byte, ver kcapver.Version) error {
	if len(b) < 34 {
		return fmt.Errorf("expected at least 34 bytes but got %d bytes", len(b))
	}

	// read seq, pid, tid
	e.Seq = bytes.ReadUint64(b[0:])
	e.PID = bytes.ReadUint32(b[8:])
	e.Tid = bytes.ReadUint32(b[12:])

	// read ktype and CPU
	var ktype ktypes.Ktype
	copy(ktype[:], b[16:33])
	e.Type = ktype
	e.CPU = b[33:34][0]

	// read event name
	l := bytes.ReadUint16(b[34:])
	buf := b[36:]
	offset := l
	e.Name = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read category
	l = bytes.ReadUint16(b[36+offset:])
	buf = b[38+offset:]
	offset += l
	e.Category = ktypes.Category(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read description
	l = bytes.ReadUint16(b[38+offset:])
	buf = b[40+offset:]
	offset += l
	e.Description = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read host name
	l = bytes.ReadUint16(b[40+offset:])
	buf = b[42+offset:]
	offset += l
	e.Host = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read timestamp
	l = bytes.ReadUint16(b[42+offset:])
	buf = b[44+offset:]
	offset += l
	if len(buf) > 0 {
		var err error
		e.Timestamp, err = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		if err != nil {
			unmarshalTimestampErrors.Add(1)
		}
	}

	// read parameters
	nparams := bytes.ReadUint16(b[44+offset:])
	// accumulates the offset of all parameter name and value lengths
	var poffset uint16

	for i := 0; i < int(nparams); i++ {
		// read kparam type
		typ := bytes.ReadUint16(b[46+offset+poffset:])
		// read kparam name
		kparamNameLength := bytes.ReadUint16(b[48+offset+poffset:])
		buf = b[50+offset+poffset:]
		kparamName := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:kparamNameLength:kparamNameLength])

		var kval kparams.Value
		switch kparams.Type(typ) {
		case kparams.AnsiString, kparams.UnicodeString:
			// read string parameter
			l := bytes.ReadUint16(b[50+offset+kparamNameLength+poffset:])
			buf = b[52+offset+kparamNameLength+poffset:]
			if len(buf) > 0 {
				kval = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
			}
			// increment parameter offset by string by type length + name length bytes + length of
			// the string parameter + string parameter size
			poffset += kparamNameLength + 6 + l
		case kparams.Uint64:
			kval = bytes.ReadUint64(b[50+offset+kparamNameLength+poffset:])
			// increment parameter offset by type length + name length sizes + size of uint64
			poffset += kparamNameLength + 4 + 8
		case kparams.Int64:
			kval = int64(bytes.ReadUint64(b[50+offset+kparamNameLength+poffset:]))
			// increment parameter offset by type length + name length sizes + size of int64
			poffset += kparamNameLength + 4 + 8
		case kparams.Double:
			kval = float64(bytes.ReadUint64(b[50+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 8
		case kparams.Float:
			kval = float32(bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 4
		case kparams.IPv4:
			kval = ip.ToIPv4(bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:]))
			// // increment by IPv4 length
			poffset += kparamNameLength + 4 + 4
		case kparams.IPv6:
			kval = ip.ToIPv6(b[50+offset+kparamNameLength+poffset : 50+offset+kparamNameLength+poffset+16])
			// increment by IPv6 length
			poffset += kparamNameLength + 4 + 16
		case kparams.PID, kparams.TID:
			kval = bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 4
		case kparams.Int32:
			kval = int32(bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 4
		case kparams.Uint32, kparams.Enum, kparams.Status:
			kval = bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 4
		case kparams.Uint16, kparams.Port:
			kval = bytes.ReadUint16(b[50+offset+kparamNameLength+poffset:])
			poffset += kparamNameLength + 4 + 2
		case kparams.Int16:
			kval = int16(bytes.ReadUint16(b[50+offset+kparamNameLength+poffset:]))
			poffset += kparamNameLength + 4 + 2
		case kparams.Uint8:
			kval = b[50+offset+kparamNameLength+poffset : 50+offset+kparamNameLength+poffset+1][0]
			poffset += kparamNameLength + 4 + 1
		case kparams.Int8:
			kval = int8(b[50+offset+kparamNameLength+poffset : 50+offset+kparamNameLength+poffset+1][0])
			poffset += kparamNameLength + 4 + 1
		case kparams.HexInt8:
			v := b[50+offset+kparamNameLength+poffset : 50+offset+kparamNameLength+poffset+1][0]
			kval = kparams.NewHex(v)
			poffset += kparamNameLength + 4 + 1
		case kparams.HexInt16:
			v := bytes.ReadUint16(b[50+offset+kparamNameLength+poffset:])
			kval = kparams.NewHex(v)
			poffset += kparamNameLength + 4 + 2
		case kparams.HexInt32:
			v := bytes.ReadUint32(b[50+offset+kparamNameLength+poffset:])
			kval = kparams.NewHex(v)
			poffset += kparamNameLength + 4 + 4
		case kparams.HexInt64:
			v := bytes.ReadUint64(b[50+offset+kparamNameLength+poffset:])
			kval = kparams.NewHex(v)
			poffset += kparamNameLength + 4 + 8
		case kparams.Bool:
			v := b[50+offset+kparamNameLength+poffset : 50+offset+kparamNameLength+poffset+1][0]
			if v == 1 {
				kval = true
			} else {
				kval = false
			}
			poffset += kparamNameLength + 4 + 1
		case kparams.Time:
			// read ts length
			l := bytes.ReadUint16(b[50+offset+kparamNameLength+poffset:])
			buf = b[52+offset+kparamNameLength+poffset:]
			if len(buf) > 0 {
				var err error
				kval, err = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
				if err != nil {
					unmarshalTimestampErrors.Add(1)
				}
			}
			poffset += kparamNameLength + 6 + l
		case kparams.Slice:
			// read slice element type
			typ := b[50+offset+kparamNameLength+poffset]
			// read slice size
			l := bytes.ReadUint16(b[51+offset+kparamNameLength+poffset:])
			var off uint16
			switch typ {
			case 's':
				s := make([]string, l)
				for i := 0; i < int(l); i++ {
					size := bytes.ReadUint16(b[53+offset+kparamNameLength+poffset+off:])
					buf := b[55+offset+kparamNameLength+poffset+off:]
					s[i] = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:size:size])
					off += 2 + size
				}
				kval = s
			}
			poffset += kparamNameLength + 4 + 1 + 2 + off
		case kparams.Binary:

		}

		if kval != nil {
			e.Kparams.AppendFromKcap(kparamName, kparams.Type(typ), kval)
		}
	}

	offset += poffset

	// read metadata tags
	ntags := bytes.ReadUint16(b[46+offset:])
	var moffset uint16
	for i := 0; i < int(ntags); i++ {
		// read key
		klen := bytes.ReadUint16(b[48+offset+moffset:])
		buf = b[50+offset+moffset:]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		// read value
		vlen := bytes.ReadUint16(b[50+offset+klen+moffset:])
		buf = b[52+offset+klen+moffset:]
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
	sec := section.Read(b[48+offset:])
	if sec.Size() != 0 {
		ps, err := ptypes.NewFromKcap(b[58+offset:], sec)
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

// MarshalJSON produces a JSON payload for this kevent.
func (e *Kevent) MarshalJSON() []byte {
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

	// start kparams
	js.writeObjectField("kparams")
	js.writeObjectStart()

	pars := make([]*Kparam, 0, len(e.Kparams))
	for _, kpar := range e.Kparams {
		pars = append(pars, kpar)
	}
	sort.Slice(pars, func(i, j int) bool { return pars[i].Name < pars[j].Name })

	for i, kpar := range pars {
		writeMore := js.shouldWriteMore(i, len(pars))
		js.writeObjectField(kpar.Name)
		switch kpar.Type {
		case kparams.Int64:
			js.writeInt64(kpar.Value.(int64))
		case kparams.Uint64:
			js.writeUint64(kpar.Value.(uint64))
		case kparams.Int32:
			js.writeInt32(kpar.Value.(int32))
		case kparams.Uint32:
			js.writeUint32(kpar.Value.(uint32))
		case kparams.Int16:
			js.writeInt16(kpar.Value.(int16))
		case kparams.Uint16, kparams.Port:
			js.writeUint16(kpar.Value.(uint16))
		case kparams.Int8:
			js.writeInt8(kpar.Value.(int8))
		case kparams.Uint8:
			js.writeUint8(kpar.Value.(uint8))
		case kparams.Float:
			js.writeFloat32(kpar.Value.(float32))
		case kparams.Double:
			js.writeFloat64(kpar.Value.(float64))
		case kparams.PID, kparams.TID:
			js.writeUint32(kpar.Value.(uint32))
		case kparams.IPv4, kparams.IPv6:
			js.writeString(kpar.Value.(net.IP).String())
		case kparams.HexInt8, kparams.HexInt16, kparams.HexInt32, kparams.HexInt64:
			js.writeString(kpar.Value.(kparams.Hex).String())
		case kparams.Bool:
			js.writeBool(kpar.Value.(bool))
		case kparams.Time:
			js.writeString(kpar.Value.(time.Time).String())
		case kparams.Slice:
			switch slice := kpar.Value.(type) {
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
			js.writeEscapeString(kpar.String())
		}
		if writeMore {
			js.writeMore()
		}
	}
	// end kparams
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
		js.writeObjectField("comm").writeEscapeString(ps.Cmdline).writeMore()
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
			js.writeObjectField("comm").writeEscapeString(parent.Cmdline).writeMore()
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
				js.writeObjectField("entrypoint").writeString(thread.Entrypoint.String()).writeMore()
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
				js.writeObjectField("object").writeEscapeString(string(kparams.NewHex(handle.Object)))
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
