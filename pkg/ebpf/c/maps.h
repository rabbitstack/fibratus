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

#define BUFFER_SIZE (1 << 14)
#define BUFFER_SIZE_MAX (BUFFER_SIZE - 1)
#define BUFFER_SIZE_HALF (BUFFER_SIZE_MAX >> 1)

struct bpf_map_def SEC("maps/stats") stats = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 0,
};

/* This map stores tracer programs with the keys being the syscall identifier
 * and the values being the eBPF program.
 */
struct bpf_map_def SEC("maps/tracers") tracers = {
        .type = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = sizeof(u16),
};

struct bpf_map_def SEC("maps/pid_discarders") pid_discarders = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 32000,
};

struct bpf_map_def SEC("maps/buffer_area") buffer_area = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = BUFFER_SIZE,
        .max_entries = BUFFER_SIZE,
};

struct bpf_map_def SEC("maps/perf") perf = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 0,
};
