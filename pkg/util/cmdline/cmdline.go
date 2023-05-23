/*
 * Copyright 2022-2023 by Nedim Sabic Sabic
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

package cmdline

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// splitRegexp declares the regular expression for splitting the string
	// by white spaces if the string is not inside a double quote.
	splitRegexp = regexp.MustCompile(`("[^"]+?"\S*|\S+)`)

	// systemRootRegexp is the regular expression for detecting path with unexpanded SystemRoot environment variable
	systemRootRegexp = regexp.MustCompile(`%SystemRoot%|^\\SystemRoot|%systemroot%`)

	// driveRegexp is used for determining if the command line start with a valid drive letter based path
	driveRegexp = regexp.MustCompile(`^[a-zA-Z]:\\`)
)

var sysProcs = map[string]bool{
	"dwm.exe":         true,
	"wininit.exe":     true,
	"winlogon.exe":    true,
	"fontdrvhost.exe": true,
	"sihost.exe":      true,
	"taskhostw.exe":   true,
	"dashost.exe":     true,
	"ctfmon.exe":      true,
	"svchost.exe":     true,
	"csrss.exe":       true,
	"services.exe":    true,
	"audiodg.exe":     true,
	"kernel32.dll":    true,
}

// Cmdline offers a convenient interface for the process command line manipulation/normalization.
type Cmdline struct {
	cmdline string
	orig    string // original command line
}

func New(cmdline string) *Cmdline {
	return &Cmdline{cmdline: cmdline, orig: cmdline}
}

// Split returns a slice of strings where each element is
// a single argument in the process command line.
func Split(cmdline string) []string { return splitRegexp.FindAllString(cmdline, -1) }

// CleanExe cleans the executable path and rejoins
// the rest of the command line arguments.
func (c *Cmdline) CleanExe() *Cmdline {
	args := Split(c.cmdline)
	if len(args) > 0 {
		exe := args[0]
		// remove quotes from executable path
		if exe[0] == '"' && exe[len(exe)-1] == '"' {
			c.cmdline = strings.Join(append([]string{exe[1 : len(exe)-1]}, args[1:]...), " ")
			return c
		}
		// remove \??\ prefix from executable path
		if len(exe) > 4 && exe[1] == '?' && exe[2] == '?' {
			c.cmdline = strings.Join(append([]string{exe[4:]}, args[1:]...), " ")
			return c
		}
	}
	return c
}

// ExpandSystemRoot expands all variations of the SystemRoot environment variable,
func (c *Cmdline) ExpandSystemRoot() *Cmdline {
	if systemRootRegexp.MatchString(c.cmdline) {
		c.cmdline = systemRootRegexp.ReplaceAllString(c.cmdline, os.Getenv("SystemRoot"))
	}
	return c
}

// CompleteSysProc completes the executable path of the missing system process.
func (c *Cmdline) CompleteSysProc(name string) *Cmdline {
	if !driveRegexp.MatchString(c.cmdline) {
		_, ok := sysProcs[name]
		if ok {
			c.cmdline = filepath.Join(os.Getenv("SystemRoot"), "System32", c.cmdline)
		}
	}
	return c
}

// Exeline returns the normalized executable path from cmdline.
func (c *Cmdline) Exeline() string {
	i := strings.Index(strings.ToLower(c.cmdline), ".exe")
	if i > 0 {
		return c.cmdline[0 : i+4] // dot + exe
	}
	return c.cmdline
}

// String returns the original command line string.
func (c *Cmdline) String() string { return c.orig }
