/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package params

import (
	"math"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestValueSize(t *testing.T) {
	if s := unsafe.Sizeof(Value{}); s != 24 {
		t.Fatalf("Value should be 24 bytes, got %d", s)
	}
}

func TestValueZeroIsNull(t *testing.T) {
	var v Value
	if !v.IsNull() || v.Kind() != KindNull {
		t.Fatal("zero value must be null")
	}
	if v.Uint64() != 0 || v.Str() != "" || v.Bytes() != nil || v.IP() != nil ||
		v.U64Slice() != nil || v.StrSlice() != nil || v.Bool() || v.Float64() != 0 ||
		!v.Time().Equal(time.Unix(0, 0)) || v.Len() != 0 {
		t.Fatal("null value must yield defaults")
	}
}

func TestValueIntegers(t *testing.T) {
	if v := U8(255); v.Uint8() != 255 || v.Uint64() != 255 || v.Bits() != 8 || v.Kind() != KindUint {
		t.Fatal("u8")
	}
	if v := U16(65535); v.Uint16() != 65535 || v.Bits() != 16 {
		t.Fatal("u16")
	}
	if v := U32(math.MaxUint32); v.Uint32() != math.MaxUint32 || v.Bits() != 32 {
		t.Fatal("u32")
	}
	if v := U64(math.MaxUint64); v.Uint64() != math.MaxUint64 || v.Bits() != 64 {
		t.Fatal("u64")
	}
	if v := I8(-8); v.Int8() != -8 || v.Int64() != -8 || v.Kind() != KindInt {
		t.Fatal("i8")
	}
	if v := I16(-16); v.Int16() != -16 || v.Int64() != -16 {
		t.Fatal("i16")
	}
	if v := I32(-32); v.Int32() != -32 || v.Int64() != -32 {
		t.Fatal("i32")
	}
	if v := I64(math.MinInt64); v.Int64() != math.MinInt64 {
		t.Fatal("i64")
	}
	// lenient narrowing / widening between integer kinds
	if U64(0x1_0000_0001).Uint32() != 1 {
		t.Fatal("narrowing")
	}
	if I32(-1).Int64() != -1 {
		t.Fatal("sign extension")
	}
	// non-integer kinds yield zero
	if Str("12").Uint64() != 0 {
		t.Fatal("string is not an integer")
	}
}

func TestValueBoolFloatTime(t *testing.T) {
	if !Boolean(true).Bool() || Boolean(false).Bool() {
		t.Fatal("bool")
	}
	if Boolean(true).Uint64() != 1 {
		t.Fatal("bool as integer")
	}
	if U32(1).Bool() {
		t.Fatal("integer is not a bool")
	}
	if F32(1.5).Float32() != 1.5 || F32(1.5).Float64() != 1.5 {
		t.Fatal("f32")
	}
	if F64(math.Pi).Float64() != math.Pi {
		t.Fatal("f64")
	}
	ts := time.Date(2026, 10, 21, 23, 22, 0, 123456789, time.UTC)
	if got := Timestamp(ts).Time(); !got.Equal(ts) {
		t.Fatalf("time: %v != %v", got, ts)
	}
	if !U64(5).Time().Equal(time.Unix(0, 0)) {
		t.Fatal("default time")
	}
}

func TestValueStringAndBytes(t *testing.T) {
	for _, s := range []string{"", "a", "C:\\Windows\\system32\\svchost.exe", strings.Repeat("x", 100000)} {
		if got := Str(s).Str(); got != s {
			t.Fatalf("string roundtrip failed for %d bytes", len(s))
		}
	}
	if Str("abc").Len() != 3 {
		t.Fatal("len")
	}
	b := []byte{1, 2, 3, 0, 5}
	if got := Bin(b).Bytes(); string(got) != string(b) {
		t.Fatal("bytes roundtrip")
	}
	if Bin(nil).Bytes() != nil && len(Bin(nil).Bytes()) != 0 {
		t.Fatal("empty bytes")
	}
	if Bin(b).Str() != "" || Str("x").Bytes() != nil {
		t.Fatal("kind mismatch must yield defaults")
	}
}

func TestValueIP(t *testing.T) {
	v := IPv4LE(0x0100007f) // 127.0.0.1 read from LE buffer: 7f 00 00 01
	if !v.IsIPv4() || v.IP().String() != "127.0.0.1" {
		t.Fatalf("ipv4le: %v", v.IP())
	}
	if IP4(192, 168, 1, 10).IP().String() != "192.168.1.10" {
		t.Fatal("ipv4")
	}
	if !IP4(10, 0, 0, 1).IP().Equal(net.ParseIP("10.0.0.1")) {
		t.Fatal("ipv4 equality with net.ParseIP")
	}
	src := net.ParseIP("2001:db8::ff00:42:8329")
	v6 := IP6(src)
	if !v6.IsIPv6() || v6.IP().String() != "2001:db8::ff00:42:8329" {
		t.Fatalf("ipv6: %v", v6.IP())
	}
	// the buffer is copied
	buf := append([]byte(nil), src...)
	v6 = IP6(buf)
	for i := range buf {
		buf[i] = 0
	}
	if v6.IP().String() != "2001:db8::ff00:42:8329" {
		t.Fatal("ipv6 must be copied")
	}
	if IP6([]byte{1, 2}).Kind() != KindNull {
		t.Fatal("short ipv6")
	}
	if IPAddr(net.ParseIP("1.2.3.4")).IP().String() != "1.2.3.4" || !IPAddr(net.ParseIP("1.2.3.4")).IsIPv4() {
		t.Fatal("ipaddr v4")
	}
	if !IPAddr(net.ParseIP("::1")).IsIPv6() {
		t.Fatal("ipaddr v6")
	}
	if IPAddr(nil).Kind() != KindNull || IPAddr(net.IP{1}).Kind() != KindNull {
		t.Fatal("ipaddr invalid")
	}
	// returned address can't be grown into the stored one
	ip := v6.IP()
	if cap(ip) != 16 {
		t.Fatal("cap")
	}
}

func TestValueSlices(t *testing.T) {
	u := []uint64{1, 2, 0xfffff80000000000}
	got := U64Slice(u).U64Slice()
	if len(got) != 3 || got[2] != 0xfffff80000000000 {
		t.Fatal("u64 slice")
	}
	if U64Slice(nil).U64Slice() != nil || U64Slice([]uint64{}).Len() != 0 {
		t.Fatal("empty u64 slice")
	}
	s := []string{"a", "bb", ""}
	gs := StrSlice(s).StrSlice()
	if len(gs) != 3 || gs[1] != "bb" {
		t.Fatal("string slice")
	}
	if StrSlice(nil).StrSlice() != nil {
		t.Fatal("nil string slice")
	}
	if !U64Slice(u).IsSlice() || !StrSlice(s).IsSlice() || Str("").IsSlice() {
		t.Fatal("IsSlice")
	}
	if U64Slice(u).StrSlice() != nil || StrSlice(s).U64Slice() != nil {
		t.Fatal("slice kind mismatch")
	}
}

// TestValueKeepsMemoryAlive makes sure the garbage collector doesn't
// reclaim the memory only referenced from the union's unsafe pointer.
func TestValueKeepsMemoryAlive(t *testing.T) {
	mk := func() []Value {
		vals := make([]Value, 0, 4)
		vals = append(vals, Str(strings.Repeat("alive", 1000)))
		ss := make([]string, 3)
		for i := range ss {
			ss[i] = strings.Repeat("s", 100+i)
		}
		vals = append(vals, StrSlice(ss))
		vals = append(vals, U64Slice([]uint64{7, 8, 9}))
		vals = append(vals, IP6(net.ParseIP("fe80::1")))
		return vals
	}
	vals := mk()
	for i := 0; i < 5; i++ {
		runtime.GC()
		// churn the heap to overwrite freed objects
		junk := make([][]byte, 0, 1000)
		for j := 0; j < 1000; j++ {
			junk = append(junk, make([]byte, 128))
		}
		_ = junk
	}
	if vals[0].Str() != strings.Repeat("alive", 1000) {
		t.Fatal("string was collected")
	}
	ss := vals[1].StrSlice()
	for i := range ss {
		if ss[i] != strings.Repeat("s", 100+i) {
			t.Fatal("string slice element was collected")
		}
	}
	if u := vals[2].U64Slice(); u[0] != 7 || u[2] != 9 {
		t.Fatal("uint slice was collected")
	}
	if vals[3].IP().String() != "fe80::1" {
		t.Fatal("ipv6 was collected")
	}
}

var sink Value
var sinkU uint64
var sinkS string

func BenchmarkValueUnionU32(b *testing.B) {
	b.ReportAllocs()
	vals := make([]Value, 8)
	for i := 0; i < b.N; i++ {
		vals[i&7] = U32(uint32(i))
		sinkU += uint64(vals[i&7].Uint32())
	}
}

func BenchmarkValueInterfaceU32(b *testing.B) {
	b.ReportAllocs()
	vals := make([]any, 8)
	for i := 0; i < b.N; i++ {
		vals[i&7] = uint32(i)
		sinkU += uint64(vals[i&7].(uint32))
	}
}

func BenchmarkValueUnionString(b *testing.B) {
	b.ReportAllocs()
	s := "C:\\Windows\\system32\\svchost.exe"
	vals := make([]Value, 8)
	for i := 0; i < b.N; i++ {
		vals[i&7] = Str(s)
		sinkS = vals[i&7].Str()
	}
}

func BenchmarkValueInterfaceString(b *testing.B) {
	b.ReportAllocs()
	s := "C:\\Windows\\system32\\svchost.exe"
	vals := make([]any, 8)
	for i := 0; i < b.N; i++ {
		vals[i&7] = s
		sinkS = vals[i&7].(string)
	}
}
