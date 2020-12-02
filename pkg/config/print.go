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

package config

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

func (c *Config) printArray(arr []interface{}) string {
	var buffer bytes.Buffer
	for v := range arr {
		buffer.WriteString(fmt.Sprintf("%v;", v))
	}
	return buffer.String()
}

func (c *Config) printMap(m map[string]interface{}) string {
	var buffer bytes.Buffer
	buffer.WriteString("[")
	for k, v := range m {
		val := c.print(v)
		if len(val) > 0 {
			buffer.WriteString(" ")
			buffer.WriteString(k)
			buffer.WriteString("=>")
			if strings.Contains(k, "password") {
				buffer.WriteString("********")
			} else {
				buffer.WriteString(val)
			}
		}
	}
	buffer.WriteString("]")
	return buffer.String()
}

func (c *Config) print(value interface{}) string {
	t := reflect.TypeOf(value)
	switch t.Kind() {
	case reflect.Array:
		return c.printArray(value.([]interface{}))
	case reflect.Map:
		return c.printMap(value.(map[string]interface{}))
	default:
		return fmt.Sprintf("%v", value)
	}
}

func (c *Config) printLine(buffer *bytes.Buffer, maxLength int, key string, value string) {
	if value != "" {
		buffer.WriteString("\n\t")
		buffer.WriteString(key)
		buffer.WriteString(" ")
		buffer.WriteString(strings.Repeat(".", maxLength-len(key)+5))
		buffer.WriteString(" ")
		buffer.WriteString(value)
	}
}

// Print returns the string with all the config options pretty-printed.
func (c *Config) Print() string {
	opts := c.viper.AllSettings()

	var buffer bytes.Buffer
	var maxKeyLen = 20

	type kv struct {
		k string
		v interface{}
	}

	sorted := make([]kv, 0, len(opts))
	// for printing we need to find the max key length
	for key, v := range opts {
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
		sorted = append(sorted, kv{k: key, v: v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].k < sorted[j].k })

	// print the options
	for _, kv := range sorted {
		c.printLine(&buffer, maxKeyLen, kv.k, c.print(kv.v))
	}

	return buffer.String()
}
