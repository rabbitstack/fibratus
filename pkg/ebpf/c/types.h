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

#define MAX_KPARS (1 << 5)      /* Max number of event parameters */
#define MAX_KPAR_NAME 32        /* Max size of the parameter name */

struct discarder_key {
    char comm[TASK_COMM_LEN];
};

struct kpar_spec {
    char name[MAX_KPAR_NAME];
    u16 type;
};

struct kpars_value {
    u32 nparams;
    struct kpar_spec specs[MAX_KPARS];
};
