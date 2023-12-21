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

package loldrivers

// RawDriver contains vulnerable/malicious driver data fetched from loldrivers API endpoint.
type RawDriver struct {
	ID                     string `json:"Id"`
	Category               string `json:"Category"`
	Created                string `json:"Created"`
	MitreID                string `json:"MitreID"`
	KnownVulnerableSamples []struct {
		Filename string `json:"Filename"`
		MD5      string `json:"MD5,omitempty"`
		SHA1     string `json:"SHA1,omitempty"`
		SHA256   string `json:"SHA256,omitempty"`
	} `json:"KnownVulnerableSamples,omitempty"`
}

func (d RawDriver) isMalicious() bool {
	return d.Category == "malicious"
}

// Driver intermediate structure for storing driver data
// relevant for the hash matching.
type Driver struct {
	Filename     string
	SHA1         string
	SHA256       string
	IsMalicious  bool
	IsVulnerable bool
}
