// +build windows

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

package tdh

import (
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	sc "syscall"
	"unsafe"
)

const (
	// IntypeNull represents the null property type
	IntypeNull = iota
	// IntypeUnicodeString represents a string of 16-bit characters. By default, assumed to have been encoded using UTF-16LE
	IntypeUnicodeString
	// IntypeAnsiString represents a string of 8-bit characters
	IntypeAnsiString
	// IntypeInt8 represents a signed 8-bit integer
	IntypeInt8
	// IntypeUint8 represents an unsigned 8-bit integer
	IntypeUint8
	// IntypeInt16 represents a signed 16-bit integer
	IntypeInt16
	// IntypeUint16 represents an unsigned 18-bit integer
	IntypeUint16
	// IntypeInt32 represents a signed 32-bit integer
	IntypeInt32
	// IntypeUint32 represents an unsigned 8-bit integer
	IntypeUint32
	// IntypeInt64 represents a signed 64-bit integer
	IntypeInt64
	// IntypeUint64 represents an unsigned 64-bit integer
	IntypeUint64
	// IntypeFloat represents an IEEE 4-byte floating-point number
	IntypeFloat
	// IntypeDouble represents an IEEE 8-byte floating-point number
	IntypeDouble
	// IntypeBoolean a 32-bit value where 0 is false and 1 is true
	IntypeBoolean
	// IntypeBinary represents a binary data of variable size
	IntypeBinary
	// IntypeGUID is a GUID structure. On output, the GUID is rendered in the registry string form, {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
	IntypeGUID
	// IntypePointer represents an unsigned 32-bit or 64-bit pointer value. The size depends on the architecture of the computer logging the event
	IntypePointer
	// IntypeFiletime represents the file timestamp
	IntypeFiletime
	// IntypeSystime represents the system timestamp
	IntypeSystime
	// IntypeSID represents a security identifier (SID) structure that uniquely identifies a user or group
	IntypeSID
	// IntypeHexInt32 represents the hexadecimal representation of 32-bit integer
	IntypeHexInt32
	// IntypeHexInt64 represents the hexadecimal representation of 64-bit integer
	IntypeHexInt64
	// IntypeUnicodeChar represents the Unicode codepoint
	IntypeUnicodeChar = 306
	// IntypeAnsiChar represents the ASCII character
	IntypeAnsiChar = 307
	// IntypeSizet represents the architecture-variable size
	IntypeSizet = 308
	// IntypeHexdump represents the hexadecimal dump
	IntypeHexdump = 309
	// IntypeWbemSID represents the Web-Based Enterprise Management security identifier
	IntypeWbemSID = 310
)

const (
	// OutypeNull represents the null property type
	OutypeNull = iota
	// OutypeString represents a string value
	OutypeString
	// OutypeDatetime represents the timestamp value
	OutypeDatetime
	// OutypeByte represents a signed 8-bit value
	OutypeByte
	// OutypeUnsignedByte represents an unsigned 8-bit value
	OutypeUnsignedByte
	// OutypeShort represents a signed 16-bit value
	OutypeShort
	// OutypeUnsignedShort represents an unsigned 16-bit value
	OutypeUnsignedShort
	// OutypeInt represents a signed 32-bit value
	OutypeInt
	// OutypeUnsignedInt represents an unsigned 32-bit value
	OutypeUnsignedInt
	// OutypeLong represents a signed 64-bit value
	OutypeLong
	// OutypeUnsignedLong represents an unsigned 64-bit value
	OutypeUnsignedLong
	// OutypeFloat represents an IEEE 4-byte floating-point number
	OutypeFloat
	// OutypeDouble represents an IEEE 8-byte floating-point number
	OutypeDouble
	// OutypeBoolean a 32-bit value where 0 is false and 1 is true
	OutypeBoolean
	// OutypeGUID represents an unsigned 32-bit or 64-bit pointer value. The size depends on the architecture of the computer logging the event
	OutypeGUID
	// OutypeHexBinary represents a binary data of variable size in hexadecimal format
	OutypeHexBinary
	// OutypeHexInt8 represents the hexadecimal representation of 8-bit integer
	OutypeHexInt8
	// OutypeHexInt16 represents the hexadecimal representation of 16-bit integer
	OutypeHexInt16
	// OutypeHexInt32 represents the hexadecimal representation of 32-bit integer
	OutypeHexInt32
	// OutypeHexInt64 represents the hexadecimal representation of 64-bit integer
	OutypeHexInt64
	// OutypePID represents the process identifier
	OutypePID
	// OutypeTID represents the thread identifier
	OutypeTID
	// OutypePort represents the port
	OutypePort
	// OutypeIPv4 represents the IPv4 address
	OutypeIPv4
	// OutypeIPv6 represents the IPv6 address
	OutypeIPv6
)

// NonStructType defines if the property is contained in a structure or array.
type NonStructType struct {
	InType        uint16
	OutType       uint16
	MapNameOffset uint32
}

// EventPropertyInfo provides information about a single property of the event or filter.
type EventPropertyInfo struct {
	Flags      int32
	NameOffset uint32
	Types      [8]byte
	Count      [2]byte
	Length     [2]byte
	Reserved   [4]byte
}

// TraceEventInfo defines the information about the event.
type TraceEventInfo struct {
	ProviderGUID           sc.GUID
	EventGUID              sc.GUID
	EventDescriptor        etw.EventDescriptor
	DecodingSource         int32
	ProviderNameOffset     uint32
	LevelNameOffset        uint32
	ChannelNameOffset      uint32
	KeywordsNameOffset     uint32
	TaskNameOffset         uint32
	OpcodeNameOffset       uint32
	EventMessageOffset     uint32
	ProviderMessageOffset  uint32
	BinaryXMLOffset        uint32
	BinaryXMLSize          uint32
	EventNameOffset        [4]byte
	EventAttributeOffset   [4]byte
	PropertyCount          uint32
	TopLevelPropertyCount  uint32
	Flags                  [4]byte
	EventPropertyInfoArray [1]EventPropertyInfo
}

// PropertyDataDescriptor defines the property to retrieve.
type PropertyDataDescriptor struct {
	PropertyName unsafe.Pointer
	ArrayIndex   uint32
	Reserved     uint32
}
