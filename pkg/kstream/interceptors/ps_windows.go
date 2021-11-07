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

package interceptors

import (
	"expvar"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
)

// systemRootRegexp is the regular expression for detecting path with unexpanded SystemRoot environment variable
var systemRootRegexp = regexp.MustCompile(`%SystemRoot%|\\SystemRoot`)

// procYaraScans stores the total count of yara process scans
var procYaraScans = expvar.NewInt("yara.proc.scans")

type psInterceptor struct {
	snap ps.Snapshotter
	yara yara.Scanner
}

var sysProcs = map[string]bool{
	"dwm.exe":         true,
	"wininit.exe":     true,
	"explorer.exe":    true,
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

// newPsInterceptor creates a new kstream interceptor for process events.
func newPsInterceptor(snap ps.Snapshotter, yara yara.Scanner) KstreamInterceptor {
	return psInterceptor{snap: snap, yara: yara}
}

func (ps psInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	typ := kevt.Type
	switch typ {
	case ktypes.CreateProcess, ktypes.TerminateProcess, ktypes.EnumProcess:
		comm, err := kevt.Kparams.GetString(kparams.Comm)
		if err != nil {
			return kevt, true, err
		}
		// some system processes are reported without the path in command line
		// or contain an empty command line arguments
		if !strings.Contains(comm, `\\:`) || comm == "" {
			_, ok := sysProcs[comm]
			if ok {
				_ = kevt.Kparams.Set(kparams.Comm, filepath.Join(os.Getenv("SystemRoot"), comm), kparams.UnicodeString)
			}
		}
		// to compose the full executable string we extract the path
		// from the process's command line by expanding the `SystemRoot`
		// env variable accordingly and also removing rubbish characters
		i := strings.Index(comm, ".exe")
		if i > 0 {
			exe := strings.Replace(comm[0:i+4], "\"", "", -1)
			if strings.Contains(exe, "SystemRoot") || strings.HasPrefix(strings.ToLower(exe), "%systemroot%") {
				exe = systemRootRegexp.ReplaceAllString(exe, os.Getenv("SystemRoot"))
			}
			kevt.Kparams.Append(kparams.Exe, kparams.UnicodeString, exe)
		}
		// convert hexadecimal PID values to integers
		pid, err := kevt.Kparams.GetHexAsUint32(kparams.ProcessID)
		if err != nil {
			return kevt, true, err
		}
		if err := kevt.Kparams.Set(kparams.ProcessID, pid, kparams.PID); err != nil {
			return kevt, true, err
		}
		ppid, err := kevt.Kparams.GetHexAsUint32(kparams.ProcessParentID)
		if err != nil {
			return kevt, true, err
		}
		if err := kevt.Kparams.Set(kparams.ProcessParentID, ppid, kparams.PID); err != nil {
			return kevt, true, err
		}

		if typ != ktypes.TerminateProcess {
			if pid != 0 {
				// get the process's start time and append it to the parameters
				started, err := getStartTime(pid)
				if err != nil {
					log.Warnf("couldn't get process (%d) start time: %v", pid, err)
				} else {
					_ = kevt.Kparams.Append(kparams.StartTime, kparams.Time, started)
				}
			}
			if ps.yara != nil && typ == ktypes.CreateProcess {
				// run yara scanner on the target process
				go func() {
					procYaraScans.Add(1)
					err := ps.yara.ScanProc(pid)
					if err != nil {
						log.Warnf("unable to run yara scanner on pid %d: %v", pid, err)
					}
				}()
			}
			return kevt, false, ps.snap.Write(kevt)
		}

		return kevt, false, ps.snap.Remove(kevt)

	case ktypes.CreateThread, ktypes.TerminateThread, ktypes.EnumThread:
		pid, err := kevt.Kparams.GetHexAsUint32(kparams.ProcessID)
		if err != nil {
			return kevt, true, err
		}
		if err := kevt.Kparams.Set(kparams.ProcessID, pid, kparams.PID); err != nil {
			return kevt, true, err
		}
		tid, err := kevt.Kparams.GetHexAsUint32(kparams.ThreadID)
		if err != nil {
			return kevt, true, err
		}
		if err := kevt.Kparams.Set(kparams.ThreadID, tid, kparams.TID); err != nil {
			return kevt, true, err
		}

		if typ != ktypes.TerminateThread {
			return kevt, false, ps.snap.Write(kevt)
		}

		return kevt, false, ps.snap.Remove(kevt)
	}

	return kevt, true, nil
}

func (psInterceptor) Name() InterceptorType { return Ps }

func (ps psInterceptor) Close() {
	if ps.yara != nil {
		ps.yara.Close()
	}
}

func getStartTime(pid uint32) (time.Time, error) {
	handle, err := process.Open(process.QueryLimitedInformation, false, pid)
	if err != nil {
		return time.Now(), err
	}
	defer handle.Close()
	started, err := process.GetStartTime(handle)
	if err != nil {
		return time.Now(), err
	}
	return started, nil
}
