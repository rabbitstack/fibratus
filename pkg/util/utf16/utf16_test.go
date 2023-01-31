/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package utf16

import (
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
	"unicode/utf16"
)

func TestDecode(t *testing.T) {
	for i := 0; i < 24; i++ {
		buf := genbuf(1 << i)
		w := string(utf16.Decode(buf))
		g := Decode(buf)
		if w != g {
			t.Errorf("mismatch on 1<<%d", i)
		}
	}
	s := []rune("Do you want café?")
	encoded := utf16.Encode(s)
	require.Equal(t, "Do you want café?", Decode(encoded))
}

func BenchmarkStdlibDecode(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	buf := genbuf(b.N)
	b.StartTimer()
	_ = string(utf16.Decode(buf))
}

func BenchmarkDecode(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	buf := genbuf(b.N)
	b.StartTimer()
	_ = Decode(buf)
}

func genbuf(n int) []uint16 {
	r := rand.New(rand.NewSource(int64(n)))
	buf := make([]rune, n)
	for i := 0; i < n; i++ {
		// simulate mostly-ASCII
		if r.Intn(100) == 0 {
			buf[i] = rune(r.Intn(0x10ffff + 1))
		} else {
			buf[i] = rune(r.Intn(1 << 7))
		}
	}
	return utf16.Encode(buf)
}
