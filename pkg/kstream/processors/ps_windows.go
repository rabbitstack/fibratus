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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"golang.org/x/sys/windows"
	"time"
)

type psProcessor struct {
	snap ps.Snapshotter
}

// newPsProcessor creates a new event processor for process events.
func newPsProcessor(snap ps.Snapshotter) Processor {
	return psProcessor{snap: snap}
}

func (p psProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Batch, bool, error) {
	switch e.Type {
	case ktypes.CreateProcess, ktypes.TerminateProcess, ktypes.ProcessRundown:
		if err := p.processEvent(e); err != nil {
			return kevent.NewBatch(e), false, err
		}
		if e.IsTerminateProcess() {
			return kevent.NewBatch(e), false, p.snap.Remove(e)
		}
		return kevent.NewBatch(e), false, p.snap.Write(e)
	case ktypes.CreateThread, ktypes.TerminateThread, ktypes.ThreadRundown:
		pid, err := e.Kparams.GetPid()
		if err != nil {
			return kevent.NewBatch(e), false, err
		}
		proc := p.snap.Find(pid)
		if proc != nil {
			e.Kparams.Append(kparams.Exe, kparams.UnicodeString, proc.Exe)
		}
		if !e.IsTerminateThread() {
			return kevent.NewBatch(e), false, p.snap.AddThread(e)
		}
		tid, err := e.Kparams.GetTid()
		if err != nil {
			return kevent.NewBatch(e), false, err
		}
		return kevent.NewBatch(e), false, p.snap.RemoveThread(pid, tid)
	case ktypes.OpenProcess, ktypes.OpenThread:
		pid, err := e.Kparams.GetPid()
		if err != nil {
			return kevent.NewBatch(e), false, err
		}
		proc := p.snap.Find(pid)
		if proc != nil {
			e.AppendParam(kparams.Exe, kparams.FilePath, proc.Exe)
			e.AppendParam(kparams.ProcessName, kparams.AnsiString, proc.Name)
		}
		return kevent.NewBatch(e), false, nil
	}
	return nil, true, nil
}

func (p psProcessor) processEvent(e *kevent.Kevent) error {
	cmndline := cmdline.New(e.GetParamAsString(kparams.Cmdline)).
		// get rid of leading/trailing quotes in the executable path
		CleanExe().
		// expand all variations of the SystemRoot environment variable
		ExpandSystemRoot().
		// some system processes are reported without the path in the command line,
		// but we can expand the path from the SystemRoot environment variable
		CompleteSysProc(e.GetParamAsString(kparams.ProcessName))

	// append executable path parameter
	e.AppendParam(kparams.Exe, kparams.FilePath, cmndline.Exeline())

	// set normalized command line
	_ = e.Kparams.SetValue(kparams.Cmdline, cmndline.String())

	if e.IsTerminateProcess() {
		return nil
	}

	// query process start time
	pid := e.Kparams.MustGetPid()
	started, err := getStartTime(pid)
	if err != nil {
		started = e.Timestamp
	}
	e.AppendParam(kparams.StartTime, kparams.Time, started)

	return nil
}

func (psProcessor) Name() ProcessorType { return Ps }
func (p psProcessor) Close()            {}

func getStartTime(pid uint32) (time.Time, error) {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Now(), err
	}
	defer windows.CloseHandle(proc)
	var (
		ct windows.Filetime
		xt windows.Filetime
		kt windows.Filetime
		ut windows.Filetime
	)
	err = windows.GetProcessTimes(proc, &ct, &xt, &kt, &ut)
	if err != nil {
		return time.Now(), err
	}
	return time.Unix(0, ct.Nanoseconds()), nil
}
