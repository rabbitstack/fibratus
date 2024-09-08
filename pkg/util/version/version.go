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

package version

import (
	"fmt"
	semver "github.com/hashicorp/go-version"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/jedib0t/go-pretty/v6/table"
)

// Version stores the SemVer release information along with the
// commit that produced the release and other useful information.
type Version struct {
	Major  int64
	Minor  int64
	Patch  int64
	Commit string
	Date   string
}

var versionRegexp = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

var version string

var once sync.Once
var sem *semver.Version

// Set initializes the version string as global variable.
func Set(v string) { version = v }

// Get returns the version string.
func Get() string {
	if IsDev() {
		return "dev"
	}
	return version
}

// IsDev determines if this is a dev version.
func IsDev() bool { return version == "0.0.0" || version == "" }

// Sem returns a semver spec.
func Sem() *semver.Version {
	once.Do(func() {
		var err error
		sem, err = semver.NewSemver(version)
		if err != nil {
			panic(err)
		}
	})
	return sem
}

// ProductToken returns a tag to be poked in User Agent headers.
func ProductToken() string { return fmt.Sprintf("fibratus/%s", version) }

// New parses the version string and return the version instance.
func New(version, commit, date string) Version {
	if version == "" {
		return Version{Commit: commit, Date: date}
	}

	toks := versionRegexp.FindStringSubmatch(version)
	if len(toks) == 0 || toks[0] != version {
		panic(fmt.Sprintf("invalid semver release: %s", version))
	}

	// split version info
	parts := strings.Split(toks[1], ".")
	major, _ := strconv.ParseInt(parts[0], 10, 64)
	minor, _ := strconv.ParseInt(parts[1], 10, 64)
	patch, _ := strconv.ParseInt(parts[2], 10, 64)

	v := Version{
		Major:  major,
		Minor:  minor,
		Patch:  patch,
		Commit: commit,
		Date:   date,
	}

	return v
}

// Render dumps the version information to stdout.
func (v Version) Render() {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)

	var version string
	if v.Major == 0 && v.Minor == 0 && v.Patch == 0 {
		version = "dev"
	} else {
		version = fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}

	t.AppendRow(table.Row{"Version", version})
	t.AppendRow(table.Row{"Commit", v.Commit})
	t.AppendRow(table.Row{"Build date", v.Date})

	t.AppendSeparator()

	t.AppendRow(table.Row{"Go compiler", runtime.Version()})

	t.Render()
}
