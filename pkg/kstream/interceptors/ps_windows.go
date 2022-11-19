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
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
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
var systemRootRegexp = regexp.MustCompile(`%SystemRoot%|^\\SystemRoot|%systemroot%`)

// driveRegexp is used for determining if the command line start with a valid drive letter based path
var driveRegexp = regexp.MustCompile(`^[a-zA-Z]:\\`)

// procYaraScans stores the total count of yara process scans
var procYaraScans = expvar.NewInt("yara.proc.scans")

type psInterceptor struct {
	snap ps.Snapshotter
	yara yara.Scanner
}

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

// newPsInterceptor creates a new kstream interceptor for process events.
func newPsInterceptor(snap ps.Snapshotter, yara yara.Scanner) KstreamInterceptor {
	return psInterceptor{snap: snap, yara: yara}
}

func (ps psInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	switch kevt.Type {
	case ktypes.CreateProcess,
		ktypes.TerminateProcess,
		ktypes.ProcessRundown:
		if err := ps.processEvent(kevt); err != nil {
			return kevt, false, err
		}
		if kevt.Type == ktypes.CreateProcess {
			ps.scanProc(kevt)
		}
		if kevt.Type == ktypes.TerminateProcess {
			return kevt, false, ps.snap.Remove(kevt)
		}
		return kevt, false, ps.snap.Write(kevt)
	case ktypes.CreateThread,
		ktypes.TerminateThread,
		ktypes.ThreadRundown:
		if kevt.Type != ktypes.TerminateThread {
			return kevt, false, ps.snap.Write(kevt)
		}
		return kevt, false, ps.snap.Remove(kevt)
	case ktypes.OpenProcess,
		ktypes.OpenThread:
		pid, err := kevt.Kparams.GetUint32(kparams.ProcessID)
		if err != nil {
			return kevt, true, err
		}
		proc := ps.snap.Find(pid)
		if proc != nil {
			kevt.AppendParam(kparams.Exe, kparams.UnicodeString, proc.Exe)
			kevt.AppendParam(kparams.ProcessName, kparams.UnicodeString, proc.Name)
		}
		return kevt, false, nil
	}
	return kevt, true, nil
}

func (ps psInterceptor) processEvent(kevt *kevent.Kevent) error {
	cmndline, err := kevt.Kparams.GetString(kparams.Cmdline)
	if err != nil {
		return err
	}
	// if leading/trailing quotes are found in the executable path, get rid of them
	args := cmdline.Split(cmndline)
	if len(args) > 0 {
		cmndline = cmdline.CleanExe(args)
	}
	// expand all variations of the SystemRoot env variable
	if systemRootRegexp.MatchString(cmndline) {
		cmndline = systemRootRegexp.ReplaceAllString(cmndline, os.Getenv("SystemRoot"))
	}
	// some system processes are reported without the path in the command line,
	// but we can expand the path from the SystemRoot environment variable
	if !driveRegexp.MatchString(cmndline) {
		proc, _ := kevt.Kparams.GetString(kparams.ProcessName)
		_, ok := sysProcs[proc]
		if ok {
			cmndline = filepath.Join(os.Getenv("SystemRoot"), "System32", cmndline)
		}
	}

	// append executable path parameter
	i := strings.Index(strings.ToLower(cmndline), ".exe")
	if i > 0 {
		exe := cmndline[0 : i+4]
		kevt.AppendParam(kparams.Exe, kparams.UnicodeString, exe)
	}
	_ = kevt.Kparams.SetValue(kparams.Cmdline, cmndline)

	// query process start time
	if kevt.Type != ktypes.TerminateProcess {
		pid, err := kevt.Kparams.GetPid()
		if err == nil {
			started, err := getStartTime(pid)
			if err != nil {
				started = kevt.Timestamp
			}
			kevt.AppendParam(kparams.StartTime, kparams.Time, started)
		}
	}
	return nil
}

func (ps psInterceptor) scanProc(kevt *kevent.Kevent) {
	if ps.yara != nil {
		pid, err := kevt.Kparams.GetPid()
		if err == nil {
			go func() {
				procYaraScans.Add(1)
				err := ps.yara.ScanProc(pid, kevt)
				if err != nil {
					log.Warnf("unable to run yara scanner on pid %d: %v", pid, err)
				}
			}()
		}
	}
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
