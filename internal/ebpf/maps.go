//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ebpf

const (
	eventsMapName         = "events"
	dropCountMapName      = "drop_count"
	scratchMapName        = "scratch"
	scratchHeapMapName    = "scratch_heap"
	enabledMapName        = "enabled"
	approverGenMapName    = "approver_gen"
	approverModeMapName   = "approver_mode"
	approverPIDMapName    = "approver_pid"
	approverPortMapName   = "approver_port"
	approverFileEqMapName = "approver_file_eq"
	approverFilePre0Name  = "approver_file_pre_0"
	approverFilePre1Name  = "approver_file_pre_1"
	approverFileHeapName  = "approver_file_heap"
	approverLPMHeapName   = "approver_lpm_heap"
	approverRejectMapName = "approver_reject"
)

// Mirrors APPR_REQ_* and EVT_TYPE_MAX in c/common/approvers.h. Both sides index
// the mode array as generation*approverTypeMax+type, so the values must agree.
const (
	approverReqPID  = 1 << 0
	approverReqFile = 1 << 1
	approverReqPort = 1 << 2
	approverTypeMax = 32
)
