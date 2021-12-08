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

struct kevent_header {
    u64 ts;         /* Timestamp in nanoseconds from epoch */
    u32 pid;        /* Process identifier that produced the event */
    u32 tid;        /* Thread identifier that produced the event */
    u32 cpu;        /* Logical core on which the event was generated */
    u32 nparams;    /* Number of event parameters */
    u16 type;       /* Event type which maps to syscall id */
};
