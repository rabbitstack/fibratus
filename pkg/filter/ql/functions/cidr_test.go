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

package functions

import (
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestCIDRContainsCall(t *testing.T) {
	call := CIDRContains{}

	res, _ := call.Call([]interface{}{net.ParseIP("192.168.1.5"), "192.168.1.0/24"})
	require.True(t, res.(bool))

	res, _ = call.Call([]interface{}{net.ParseIP("216.58.201.174"), "216.58.201.1/24"})
	require.True(t, res.(bool))

	res, _ = call.Call([]interface{}{"192.168.1.5", "192.168.1.0/24"})
	require.True(t, res.(bool))

	res, _ = call.Call([]interface{}{net.ParseIP("192.168.1.5"), "172.168.1.0/24"})
	require.False(t, res.(bool))

	res, _ = call.Call([]interface{}{net.ParseIP("192.168.1.5"), "172.168.1.0/24", "192.168.1.0/24"})
	require.True(t, res.(bool))

	res, _ = call.Call([]interface{}{net.ParseIP("192.168.1.5"), "192.168.1.0"})
	require.False(t, res.(bool))

	res, _ = call.Call([]interface{}{net.ParseIP("192.168.1.5")})
	require.False(t, res.(bool))
}
