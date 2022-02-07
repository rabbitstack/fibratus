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

package types

// A MatchRule represents a rule successfully matched against a block
// of data.
type MatchRule struct {
	Rule      string        `json:"rule"`
	Namespace string        `json:"namespace"`
	Tags      []string      `json:"tags"`
	Metas     []Meta        `json:"metas"`
	Strings   []MatchString `json:"strings"`
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string `json:"name"`
	Base   uint64 `json:"base"`
	Offset uint64 `json:"offset"`
	Data   []byte `json:"data"`
}

// Meta represents a rule meta variable. Value can be of type string,
// int, boolean, or nil.
type Meta struct {
	Identifier string      `json:"identifier"`
	Value      interface{} `json:"value"`
}
