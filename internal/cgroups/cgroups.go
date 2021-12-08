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

package cgroups

import (
	"io/ioutil"
	"os"
	"regexp"
)

// cgroupContainerRegexp represents the regular expression for matching the process' cgroup
// hierarchy pertaning to container engines and orchestration platforms.
//
// docker - regular Docker containers
// lxc - Linux containers
// kubepods - Kubernetes-managed containers
// ecs - ECS (Elastic Container service) containers
// libpod - podman containers
// crio - crio runtime containers
//
var cgroupContainerRegexp = regexp.MustCompile("docker|lxc|kubepods|ecs|libpod|crio")

// IsContainerized determines whether the current process is running in a container.
var IsContainerized = matchesContainerCgroup()

// IsInKubernetes determines whether the current process is running in Kubernetes pod.
var IsInKubernetes = IsContainerized && os.Getenv("KUBERNETES_PORT_443_TCP") != ""

func matchesContainerCgroup() bool {
	f, err := ioutil.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	return cgroupContainerRegexp.MatchString(string(f))
}
