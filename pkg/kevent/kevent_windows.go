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

import "github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

// IsNetworkTCP determines whether the kevent pertains to network TCP events.
func (kevt Kevent) IsNetworkTCP() bool {
	return kevt.Type != ktypes.RecvUDPv4 && kevt.Type != ktypes.RecvUDPv6 && kevt.Type != ktypes.SendUDPv4 && kevt.Type != ktypes.SendUDPv6
}

// IsNetworkUDP determines whether the kevent pertains to network UDP events.
func (kevt Kevent) IsNetworkUDP() bool {
	return kevt.Type == ktypes.RecvUDPv4 || kevt.Type == ktypes.RecvUDPv6 || kevt.Type == ktypes.SendUDPv4 || kevt.Type == ktypes.SendUDPv6
}
