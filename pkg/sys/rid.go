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

package sys

const (
	// UntrustedRid designates the integrity level of anonymous
	// logged on processes. Write access is mostly blocked.
	UntrustedRid = 0x00000000

	// LowRid designates low process token integrity. Used for
	// AppContainers, browsers that access the Internet and
	// prevent most write access to objects on the system.
	LowRid              = 0x00001000
	MediumRid           = 0x00002000
	MediumPlusRid       = MediumRid | 0x100
	HighRid             = 0x00003000
	SystemRid           = 0x00004000
	ProtectedProcessRid = 0x00005000
)

//-1                                            Unknown
//SECURITY_MANDATORY_UNTRUSTED_RID              0x00000000 Untrusted.
//SECURITY_MANDATORY_LOW_RID                    0x00001000 Low integrity.
//SECURITY_MANDATORY_MEDIUM_RID                 0x00002000 Medium integrity.
//SECURITY_MANDATORY_MEDIUM_PLUS_RID            SECURITY_MANDATORY_MEDIUM_RID + 0x100 Medium high integrity.
//SECURITY_MANDATORY_HIGH_RID                   0X00003000 High integrity.
//SECURITY_MANDATORY_SYSTEM_RID                 0x00004000 System integrity.
//SECURITY_MANDATORY_PROTECTED_PROCESS_RID      0x00005000 Protected process.
