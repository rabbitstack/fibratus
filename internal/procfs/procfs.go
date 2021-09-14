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

package procfs

import "os"

// Path returns the path to the procfs. In container envs this path
// is overridden and points to the bind-mount location as specified
// when deploying the container. This function attempts to get the
// procfs location from the `PROCFS` environment variable and fallbacks
// to `/proc` if the env variable is not defined.
func Path() string {
	if path := os.Getenv("PROCFS"); path != "" {
		return path
	}
	return "/proc"
}
