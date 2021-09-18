//go:build windows
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

package pe

import "math"

// entropy calculates the entropy of the PE section's data. This function relies
// on Shannon Entropy formula to calculate the entropy. High entropy scores mean
// that there is a high variety of frequency over data located in sections.
func entropy(data []byte) float64 {
	entropy := 0.0
	frq := make(map[byte]int, len(data))

	// get the frequency of each rune
	for _, i := range data {
		frq[i]++
	}

	for _, value := range frq {
		k := float64(value) / float64(len(data))
		entropy -= k * math.Log2(k)
	}

	return entropy
}
