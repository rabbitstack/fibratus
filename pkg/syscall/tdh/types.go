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
	IntypeNull = iota
	IntypeUnicodeString
	IntypeAnsiString
	IntypeInt8
	IntypeUint8
	IntypeInt16
	IntypeUint16
	IntypeInt32
	IntypeUint32
	IntypeInt64
	IntypeUint64
	IntypeFloat
	IntypeDouble
	IntypeBoolean
	IntypeBinary
	IntypeGUID
	IntypePointer
	IntypeFiletime
	IntypeSystime
	IntypeSID
	IntypeHexInt32
	IntypeHexInt64
	IntypeCountedString             = 300
	IntypeCountedAnsiString         = 301
	IntypeReversedCountedString     = 302
	IntypeReversedCountedAnsiString = 303
	IntypeNoNullTerminatedString    = 304
	IntypeNoNulTerminatedAnsiString = 305
	IntypeUnicodeChar               = 306
	IntypeAnsiChar                  = 307
	IntypeSizet                     = 308
	IntypeHexdump                   = 309
	IntypeWbemSID                   = 310
)

const (
	OutypeNull = iota
	OutypeString
	OutypeDatetime
	OutypeByte
	OutypeUnsignedByte
	OutypeShort
	OutypeUnsignedShort
	OutypeInt
	OutypeUnsignedInt
	OutypeLong
	OutypeUnsignedLong
	OutypeFloat
	OutypeDouble
	OutypeBoolean
	OutypeGUID
	OutypeHexBinary
	OutypeHexInt8
	OutypeHexInt16
	OutypeHexInt32
	OutypeHexInt64
	OutypePID
	OutypeTID
	OutypePort
	OutypeIPv4
	OutypeIPv6
	OutypeSocketAddress
	OutypeCIMDatetime
	OutypeETWTime
	OutypeXML
	OUTYTPEErrorCode
	OutypeReducedString = 300
)

type NonStructType struct {
	InType        uint16
	OutType       uint16
	MapNameOffset uint32
}

type EventPropertyInfo struct {
	Flags      int32
	NameOffset uint32
	Types      [8]byte
	Count      [2]byte
	Length     [2]byte
	Reserved   [4]byte
}

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

type PropertyDataDescriptor struct {
	PropertyName unsafe.Pointer
	ArrayIndex   uint32
	Reserved     uint32
}
