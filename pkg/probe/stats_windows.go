/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import "expvar"

var (
	// totalRundownFiles counts the number of opened files
	totalRundownFiles = expvar.NewInt("fs.total.rundown.files")

	// totalMapRundownFiles counts the number of memory-mapped files
	totalMapRundownFiles = expvar.NewInt("fs.total.map.rundown.files")

	// fileObjectMisses computes file object cache misses
	fileObjectMisses = expvar.NewInt("fs.file.objects.misses")

	fsApproverApprovals = expvar.NewInt("approver.fs.approvals")

	fsApproverRejections = expvar.NewInt("approver.fs.rejections")

	registryApproverApprovals = expvar.NewInt("approver.registry.approvals")

	registryApproverRejections = expvar.NewInt("approver.registry.rejections")

	procApproverApprovals = expvar.NewInt("approver.proc.approvals")

	procApproverRejections = expvar.NewInt("approver.proc.rejections")
)
