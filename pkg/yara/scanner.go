//go:build yara
// +build yara

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

package yara

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"os"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/yara/config"
	ytypes "github.com/rabbitstack/fibratus/pkg/yara/types"
	log "github.com/sirupsen/logrus"
)

var (
	// ruleMatches computes all the rule matches
	ruleMatches = expvar.NewInt("yara.rule.matches")
	// rulesInCompiler keeps the counter of the number of rules in the compiler
	rulesInCompiler = expvar.NewInt("yara.rules.in.compiler")
	// totalScans computes the number of process/file scans
	totalScans = expvar.NewInt("yara.total.scans")
)

type scanner struct {
	c      *yara.Compiler
	rules  *yara.Rules
	config config.Config

	psnap ps.Snapshotter
}

// NewScanner creates a new YARA scanner.
func NewScanner(psnap ps.Snapshotter, config config.Config) (Scanner, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("unable to create yara compiler: %v", err)
	}
	// add yara rules from file system paths by walking the dirs recursively
	for _, dir := range config.Rule.Paths {
		f, err := os.Stat(dir.Path)
		if err != nil {
			log.Warnf("cannot access %q rule path: %v", dir.Path, err)
			continue
		}
		if !f.IsDir() {
			continue
		}
		err = filepath.Walk(dir.Path, func(path string, fi os.FileInfo, err error) error {
			if filepath.Ext(path) != ".yar" {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				log.Warnf("cannot open the rule %q: %v", path, err)
				return nil
			}
			err = c.AddFile(f, dir.Namespace)
			_ = f.Close()
			if err != nil {
				log.Warnf("couldn't add %s rule: %v", fi.Name(), err)
				return nil
			}
			rulesInCompiler.Add(1)

			return nil
		})
		if err != nil {
			log.Warnf("couldn't walk %s path: %v", dir.Path, err)
		}
	}

	// add yara rules from config strings
	for _, s := range config.Rule.Strings {
		err := c.AddString(s.String, s.Namespace)
		if err != nil {
			log.Warnf("couldn't add %s rule string: %v", s.String, err)
			continue
		}
		rulesInCompiler.Add(1)
	}

	if len(c.Errors) > 0 {
		return nil, parseCompilerErrors(c.Errors)
	}

	rules, err := c.GetRules()
	if err != nil {
		return nil, fmt.Errorf("couldn't compile yara rules: %v", err)
	}

	return &scanner{
		c:      c,
		rules:  rules,
		config: config,
		psnap:  psnap,
	}, nil
}

// newInternalScanner creates a new instance of the go-yara scanner.
func (s scanner) newInternalScanner() (*yara.Scanner, error) {
	sn, err := yara.NewScanner(s.rules)
	if err != nil {
		return nil, fmt.Errorf("fail to create yara scanner: %v", err)
	}
	// set scan flags
	var flags yara.ScanFlags
	if s.config.FastScanMode {
		flags |= yara.ScanFlagsFastMode
	}
	sn.SetFlags(flags)
	sn.SetTimeout(s.config.ScanTimeout)
	return sn, nil
}

func parseCompilerErrors(errors []yara.CompilerMessage) error {
	errs := make([]error, len(errors))
	for i, err := range errors {
		errs[i] = fmt.Errorf("%s, filename: %s line: %d", err.Text, err.Filename, err.Line)
	}
	return multierror.Wrap(errs...)
}

func (s scanner) CanEnqueue() bool { return false }

func (s scanner) ProcessEvent(evt *kevent.Kevent) (bool, error) {
	return s.Scan(evt)
}

// Scan initiates the Yara rule scan when the specific signal is observed.
func (s scanner) Scan(e *kevent.Kevent) (bool, error) {
	var matches yara.MatchRules
	var isScanned bool
	var err error

	switch e.Type {
	case ktypes.CreateProcess:
		// scan the created child process
		pid := e.Kparams.MustGetPid()
		log.Debugf("scanning child process. pid: %d, exe: %s", pid, e.GetParamAsString(kparams.Exe))
		matches, err = s.scan(pid)
		isScanned = true
	case ktypes.LoadImage:
		// scan the process loading unsigned/untrusted module
		pid := e.PID
		filename := evt.GetParamAsString(kparams.ImageFilename)
		log.Debugf("scanning unsigned/untrusted module. pid: %d, module: %s", pid, filename)
		matches, err = s.scan(pid)
		isScanned = true
	case ktypes.CreateFile:
		// scan dropped PE files
		isScanned = true
	case ktypes.VirtualAlloc:
		// scan process allocating RWX memory region
		if e.PID != 4 && e.Kparams.TryGetUint32(kparams.MemProtect) == windows.PAGE_EXECUTE_READWRITE {
			log.Debugf("scanning RWX allocation. pid: %d, exe: %s, addr: %s", pid, e.GetParamAsString(kparams.Exe),
				e.GetParamAsString(kparams.MemBaseAddress))
			matches, err = s.scan(pid)
			isScanned = true
		}
	case ktypes.MapViewFile:
		// scan process mapping RX view of section
		isScanned = true
	case ktypes.RegSetValue:
		// scan registry binary values
		isScanned = true
	}

	if err != nil {
		return false, err
	}
	if len(matches) == 0 || !isScanned {
		return false, nil
	}

	if isScanned {
		totalScans.Add(1)
	}

	ruleMatches.Add(int64(len(matches)))

	return len(matches) > 0, s.emit(matches, err)
}

func (s scanner) scan(target any) (yara.MatchRules, error) {
	var matches yara.MatchRules
	sn, err := s.newInternalScanner()
	if err != nil {
		return nil, err
	}

	switch n := target.(type) {
	case uint32: // pid
		// skip the scan for this process?
		//_, proc := s.psnap.Find(pid)
		//if proc == nil {
		//	return false, fmt.Errorf("%d process not found in snapshotter", pid)
		//}
		err = sn.SetCallback(&matches).ScanProc(int(n))
	case string: // file
		err = sn.SetCallback(&matches).ScanFile(n)
	case []byte: // mem
		err = sn.SetCallback(&matches).ScanMem(n)
	}
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func (s scanner) emit(matches yara.MatchRules, e *kevent.Kevent) error {
	senders := alertsender.FindAll()
	if len(senders) == 0 {
		return fmt.Errorf("no alertsenders registered. Alert won't be sent")
	}

	title := s.config.AlertTitle(e.Category == ktypes.File || e.Category == ktypes.Registry)

	for _, match := range matches {
		// encode rule matches as JSON and append to event metadata
		m := ytypes.MatchRule{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Metas:     make([]ytypes.Meta, 0),
			Strings:   make([]ytypes.MatchString, 0),
		}
		for _, meta := range m.Metas {
			m.Metas = append(match.Metas, ytypes.Meta{Value: meta.Value, Identifier: meta.Identifier})
		}
		for _, s := range m.Strings {
			m.Strings = append(match.Strings, ytypes.MatchString{Name: s.Name, Base: s.Base, Data: s.Data, Offset: s.Offset})
		}
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		e.AddMeta(kevent.YaraMatchesKey, string(b))

		text, err := s.config.AlertText(match)
		if err != nil {
			return true, err
		}
		// send alert via all registered alert senders
		for _, sender := range senders {
			log.Infof("sending alert: [%s]. Text: %s Event: %s", title, text, e.String())

			alert := alertsender.NewAlert(
				title,
				text,
				m.Tags,
				m.SeverityFromScore(),
			)

			id := m.ID()
			// generate id if it doesn't exist in meta fields
			if id == "" {
				id = uuid.New().String()
			}
			alert.ID = id
			alert.Events = []*kevent.Kevent{e}
			alert.Labels = m.Labels()
			alert.Description = m.Description()
		}
	}
}

func (s scanner) Close() {
	if s.c != nil {
		s.c.Destroy()
	}
}
