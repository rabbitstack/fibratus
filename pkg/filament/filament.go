//go:build filament && windows
// +build filament,windows

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

package filament

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/kcap"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filament/cpython"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/term"
	log "github.com/sirupsen/logrus"

	// initialize alert senders
	_ "github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	_ "github.com/rabbitstack/fibratus/pkg/alertsender/slack"
)

// pyver designates the current Python version
const pyver = "310"

// useEmbeddedPython instructs the filament engine to use the embedded Python distribution.
var useEmbeddedPython = false

const (
	intervalFn      = "interval"
	columnsFn       = "columns"
	sortbyFn        = "sort_by"
	kfilterFn       = "kfilter"
	addRowFn        = "add_row"
	maxRowsFn       = "max_rows"
	titleFn         = "title"
	renderTableFn   = "render_table"
	findHandleFn    = "find_handle"
	findHandlesFn   = "find_handles"
	findProcessFn   = "find_process"
	findProcessesFn = "find_processes"
	emitAlertFn     = "emit_alert"

	readKcapFn = "read_kcap"

	onInitFn       = "on_init"
	onStopFn       = "on_stop"
	onNextKeventFn = "on_next_kevent"
	onIntervalFn   = "on_interval"

	doc      = "__doc__"
	headless = "__headless__"
	kcapped  = "__kcapped__"
)

var (
	keventErrors        = expvar.NewMap("filament.kevent.errors")
	keventProcessErrors = expvar.NewInt("filament.kevent.process.errors")
	kdictErrors         = expvar.NewInt("filament.kdict.errors")
	batchFlushes        = expvar.NewInt("filament.kevent.batch.flushes")

	errFilamentsDir = func(path string) error { return fmt.Errorf("%s does not exist or is not a directory", path) }

	errNoDoc                    = errors.New("filament description is required")
	errNoOnNextKevent           = errors.New("required on_next_kevent function is not defined")
	errOnNextKeventNotCallable  = errors.New("on_next_kevent is not callable")
	errOnNextKeventMismatchArgs = func(c uint32) error { return fmt.Errorf("expected 1 argument for on_next_kevent but found %d args", c) }
	errEmptyName                = errors.New("filament name is empty")

	tableOutput io.Writer
)

type kbatch []*kevent.Kevent

func (k *kbatch) append(kevt *kevent.Kevent) {
	if *k == nil {
		*k = make([]*kevent.Kevent, 0)
	}
	*k = append(*k, kevt)
}

func (k *kbatch) reset()  { *k = nil }
func (k kbatch) len() int { return len(k) }

type filament struct {
	name     string
	sortBy   string
	interval time.Duration
	columns  []string
	fexpr    string
	fnerrs   chan error
	close    chan struct{}
	gil      *cpython.GIL

	tick *time.Ticker
	mod  *cpython.Module

	config *config.Config

	psnap  ps.Snapshotter
	hsnap  handle.Snapshotter
	filter filter.Filter

	kcapFile string

	initErrors []error

	onNextKevent *cpython.PyObject
	onStop       *cpython.PyObject

	table tab
}

// New creates a new instance of the filament by starting an embedded Python interpreter. It imports the filament
// module and anchors required functions for controlling the filament options as well as providing the access to
// the kernel event flow.
func New(
	name string,
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
) (Filament, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if useEmbeddedPython {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		pylib := filepath.Join(filepath.Dir(exe), "..", "Python", fmt.Sprintf("python%s.zip", pyver))
		if _, err := os.Stat(pylib); err != nil {
			return nil, fmt.Errorf("python lib not found: %v", err)
		}
		// set the default module search path, so it points to our embedded Python distribution
		cpython.SetPath(pylib)
	}

	if name == "" {
		return nil, errEmptyName
	}

	// split filament args. The first argument
	// is the filament name followed by comma
	// separated list of arguments
	args := strings.Split(name, ",")
	if len(args) == 0 {
		return nil, errEmptyName
	}
	filamentName := args[0]

	// initialize the Python interpreter
	if err := cpython.Initialize(); err != nil {
		return nil, err
	}
	// set sys.argv
	cpython.SetSysArgv(args)

	// set the PYTHON_PATH to the filaments directory so the interpreter
	// is aware of our filament module prior to its loading
	path := config.Filament.Path
	fstat, err := os.Stat(path)
	if err != nil || !fstat.IsDir() {
		return nil, errFilamentsDir(path)
	}
	filaments, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	// check if the filament is present in the directory
	var (
		exists bool
		inDir  bool
	)
	for _, f := range filaments {
		switch f.IsDir() {
		case true:
			inDir = true
			// the filament is packed within directory
			// where we expect to find the __init__.py file
			if f.Name() == filamentName {
				exists = true
				_, err := os.Stat(filepath.Join(path, f.Name(), "__init__.py"))
				if err != nil {
					if os.IsNotExist(err) {
						return nil, fmt.Errorf("__init__.py is missing in %s filament", filamentName)
					}
					return nil, err
				}
			}
		case false:
			ext := filepath.Ext(f.Name())
			if ext != ".py" {
				continue
			}
			if strings.TrimSuffix(f.Name(), ext) == filamentName {
				exists = true
				inDir = false
			}
		}
		// filament was found
		if exists {
			break
		}
	}

	if !exists {
		return nil, fmt.Errorf("%q filament does not exist. Run 'fibratus list filaments' to view available filaments", name)
	}

	cpython.AddPythonPath(path)

	mod, err := cpython.NewModule(modName(filamentName, inDir))
	if err != nil {
		if err = cpython.FetchErr(); err != nil {
			return nil, err
		}
		return nil, err
	}
	// ensure required attributes are present before proceeding with
	// further initialization. For instance, if the documentation
	// string is not provided, on_next_kevent function is missing
	// or has a wrong signature we won't run the filament
	doc, err := mod.GetAttrString(doc)
	if err != nil || doc.IsNull() {
		return nil, errNoDoc
	}
	defer doc.DecRef()

	f := &filament{
		name:       name,
		mod:        mod,
		config:     config,
		psnap:      psnap,
		hsnap:      hsnap,
		close:      make(chan struct{}, 1),
		fnerrs:     make(chan error, 100),
		gil:        cpython.NewGIL(),
		columns:    make([]string, 0),
		interval:   time.Second,
		initErrors: make([]error, 0),
		table:      newTable(),
	}

	// check for the presence of mandatory on_next_kevent
	// function if filament is not set up in headless mode
	if !f.isHeadless() {
		if !mod.HasAttr(onNextKeventFn) {
			return nil, errNoOnNextKevent
		}
		onNextKevent, err := mod.GetAttrString(onNextKeventFn)
		if err != nil || onNextKevent.IsNull() {
			return nil, errNoOnNextKevent
		}
		if !onNextKevent.IsCallable() {
			return nil, errOnNextKeventNotCallable
		}
		argCount := onNextKevent.CallableArgCount()
		if argCount != 1 {
			return nil, errOnNextKeventMismatchArgs(argCount)
		}
		f.onNextKevent = onNextKevent
	}

	if mod.HasAttr(onStopFn) {
		f.onStop, _ = mod.GetAttrString(onStopFn)
	}
	// register all the functions for interacting with filament
	// within the Python module
	err = f.mod.RegisterFn(addRowFn, f.addRowFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(renderTableFn, f.renderTableFn, cpython.MethNoArgs)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(titleFn, f.titleFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(sortbyFn, f.sortByFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(maxRowsFn, f.maxRowsFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(columnsFn, f.columnsFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(kfilterFn, f.kfilterFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(intervalFn, f.intervalFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(emitAlertFn, f.emitAlertFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(findHandleFn, f.findHandleFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(findHandlesFn, f.findHandlesFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(findProcessFn, f.findProcessFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(findProcessesFn, f.findProcessesFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}
	err = f.mod.RegisterFn(readKcapFn, f.readKcapFn, cpython.DefaultMethFlags)
	if err != nil {
		return nil, err
	}

	// add an attribute to indicate if the filament was run from the capture
	isKcap := cpython.NewPyObjectFromValue(config.KcapFile != "")
	defer isKcap.DecRef()
	if err := mod.SetAttrString(kcapped, isKcap.RawPyObject()); err != nil {
		return nil, err
	}
	// invoke the on_init function if it has been declared in the filament
	if mod.HasAttr(onInitFn) {
		onInit, _ := mod.GetAttrString(onInitFn)
		if !onInit.IsNull() {
			onInit.Call()
			if err := cpython.FetchErr(); err != nil {
				return nil, fmt.Errorf("filament init error: %v", err)
			}
			if len(f.initErrors) > 0 {
				return nil, multierror.Wrap(f.initErrors...)
			}
		}
	}

	// initialize the console frame buffer
	var fb io.Writer
	if len(f.columns) > 0 {
		fb, err = term.NewFrameBuffer()
		if err != nil {
			return nil, fmt.Errorf("couldn't create console frame buffer: %v", err)
		}
	}
	if fb != nil {
		f.table.setWriter(fb)
		f.table.setColumnConfigs(f.columns, term.GetColumns()/2+15)
	} else if tableOutput != nil {
		f.table.setWriter(tableOutput)
	} else {
		f.table.setWriter(os.Stdout)
	}
	if len(f.columns) > 0 && f.sortBy != "" {
		var sortBy bool
		for _, col := range f.columns {
			if col == f.sortBy {
				sortBy = true
				break
			}
		}
		if !sortBy {
			return nil, fmt.Errorf("%s column can't be sorted since it is not defined", f.sortBy)
		}
	}

	// compile filter from the expression
	if f.fexpr != "" {
		f.filter = filter.New(f.fexpr, config)
		if err := f.filter.Compile(); err != nil {
			return nil, err
		}
	}
	// if on_interval function has been declared in the module, we'll
	// schedule the ticker to the interval value set during filament
	// bootstrap in on_init function or otherwise we'll use the default interval
	if mod.HasAttr(onIntervalFn) {
		onInterval, err := mod.GetAttrString(onIntervalFn)
		if err == nil && !onInterval.IsNull() {
			f.tick = time.NewTicker(f.interval)
			go f.onInterval(onInterval)
		}
	}
	// we acquired the GIL as a side effect of threading initialization (the call to cpython.Initialize())
	// but now we have to reset the current thread state and release the GIL. It is the responsibility of
	// the caller to acquire the GIL before executing any Python code from now on
	f.gil.SaveThread()

	return f, nil
}

func modName(filamentName string, inDir bool) string {
	if inDir {
		return filamentName + "." + "__init__"
	}
	return filamentName
}

func (f *filament) IsHeadless() bool {
	f.gil.Lock()
	defer f.gil.Unlock()
	return f.isHeadless()
}

// isHeadless consults the __headless__ attribute
// of the filament module to figure out whether it
// was set up in headless mode.
func (f *filament) isHeadless() bool {
	attr, err := f.mod.GetAttrString(headless)
	if err != nil || attr.IsNull() {
		return false
	}
	defer attr.DecRef()
	isHeadless, err := strconv.ParseBool(strings.ToLower(attr.String()))
	if err != nil {
		return false
	}
	return isHeadless
}

func (f *filament) Run(kevents chan *kevent.Kevent, errs chan error) error {
	var batch kbatch
	var flusher = time.NewTicker(time.Second)
	for {
		select {
		case <-f.close:
			flusher.Stop()
			return nil
		default:
		}

		select {
		case kevt := <-kevents:
			batch.append(kevt)
		case err := <-errs:
			keventErrors.Add(err.Error(), 1)
		case <-flusher.C:
			batchFlushes.Add(1)
			if batch.len() > 0 {
				err := f.pushKevents(batch)
				if err != nil {
					log.Warnf("on_next_kevent failed: %v", err)
					keventProcessErrors.Add(1)
				}
				batch.reset()
			}
		case err := <-f.fnerrs:
			return err
		case <-f.close:
			flusher.Stop()
			return nil
		}
	}
}

func (f *filament) pushKevents(b kbatch) error {
	f.gil.Lock()
	defer f.gil.Unlock()
	for _, kevt := range b {
		kdict, err := newKDict(kevt)
		kevt.Release()
		if err != nil {
			kdict.DecRef()
			kdictErrors.Add(1)
			continue
		}
		r := f.onNextKevent.Call(kdict.Object())
		if r != nil {
			r.DecRef()
		}
		kdict.DecRef()
		if err := cpython.FetchErr(); err != nil {
			return err
		}
	}
	return nil
}

func (f *filament) Close() error {
	if f.onStop != nil && !f.onStop.IsNull() {
		f.gil.Lock()
		f.onStop.Call()
		f.gil.Unlock()
	}
	f.close <- struct{}{}
	if f.tick != nil {
		f.close <- struct{}{}
	}
	if f.tick != nil {
		f.tick.Stop()
	}
	return nil
}

func (f *filament) Filter() filter.Filter { return f.filter }

func (f *filament) intervalFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.interval = time.Second * time.Duration(args.GetInt(1))
	if f.interval == 0 {
		f.initErrors = append(f.initErrors, errors.New("invalid interval value specified"))
	}
	return cpython.NewPyNone()
}

func (f *filament) sortByFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.sortBy = args.GetString(1)
	f.table.sortBy(f.sortBy)
	return cpython.NewPyNone()
}

func (f *filament) maxRowsFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.table.maxRows(args.GetInt(1))
	return cpython.NewPyNone()
}

func (f *filament) columnsFn(_, args cpython.PyArgs) cpython.PyRawObject {
	var err error
	f.columns, err = args.GetStringSlice(1)
	if err != nil {
		f.initErrors = append(f.initErrors, err)
	}
	f.table.appendHeader(f.columns)
	return cpython.NewPyNone()
}

func (f *filament) kfilterFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.fexpr = args.GetString(1)
	return cpython.NewPyNone()
}

func (f *filament) addRowFn(_, args cpython.PyArgs) cpython.PyRawObject {
	s, err := args.GetSlice(1)
	if err != nil {
		f.fnerrs <- err
		return cpython.NewPyNone()
	}
	if len(s) != len(f.columns) {
		f.fnerrs <- fmt.Errorf("add_row has %d row(s) but expected %d rows(s)", len(s), len(f.columns))
		return cpython.NewPyNone()
	}
	f.table.appendRow(s)
	return cpython.NewPyLong(int64(len(s)))
}

func (f *filament) renderTableFn(_ cpython.PyArgs, args cpython.PyArgs) cpython.PyRawObject {
	f.table.render()
	f.table.reset()
	return cpython.NewPyNone()
}

func (f *filament) titleFn(_ cpython.PyArgs, args cpython.PyArgs) cpython.PyRawObject {
	f.table.title(args.GetString(1))
	return cpython.NewPyNone()
}

var keywords = []string{"", "", "severity", "tags"}

func (f *filament) emitAlertFn(_, args cpython.PyArgs, kwargs cpython.PyKwargs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	senders := alertsender.FindAll()
	if len(senders) == 0 {
		log.Warn("no alertsenders registered. Alert won't be sent")
		return cpython.NewPyNone()
	}

	title, text, sever, tags := cpython.PyArgsParseKeywords(args, kwargs, keywords)

	for _, s := range senders {
		alert := alertsender.NewAlert(
			title,
			text,
			tags,
			alertsender.ParseSeverityFromString(sever),
		)
		if err := s.Send(alert); err != nil {
			log.Warnf("unable to emit alert from filament: %v", err)
		}
	}

	return cpython.NewPyNone()
}

func (f *filament) findProcessFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	return cpython.NewPyNone()
}

func (f *filament) findHandleFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	return cpython.NewPyNone()
}

func (f *filament) findProcessesFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	return cpython.NewPyNone()
}

func (f *filament) findHandlesFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	return cpython.NewPyNone()
}

func (f *filament) readKcapFn(_, args cpython.PyArgs) cpython.PyRawObject {
	f.gil.Lock()
	defer f.gil.Unlock()
	kevents := cpython.NewList(0)

	// set up filter and kcap reader
	expr := args.GetString(1)
	var ff filter.Filter
	if expr != "" {
		ff = filter.New(expr, f.config)
		if err := ff.Compile(); err != nil {
			cpython.SetRuntimeErr(fmt.Sprintf("bad filter in read_kcap: %v", err))
			return cpython.NewPyNone()
		}
	}
	r, err := kcap.NewReader(f.config.KcapFile, true, f.config)
	if err != nil {
		cpython.SetRuntimeErr(fmt.Sprintf("unable to set up kcap reader: %v", err))
		return cpython.NewPyNone()
	}
	if err := r.ForwardSnapshotters(); err != nil {
		cpython.SetRuntimeErr(fmt.Sprintf("fatal kcap forward: %v", err))
		return cpython.NewPyNone()
	}
	r.SetFilter(ff)

	// consume events from kcap and produce Python
	// dictionary objects that are appended to the
	// list which the kcap_read function returns
	kevtsCh, eokc, errCh := r.Read(context.Background())
	for {
		select {
		case kevt := <-kevtsCh:
			kdict, err := newKDict(kevt)
			kevt.Release()
			if err != nil {
				kdict.DecRef()
				continue
			}
			kevents.Append(kdict.Object())
			kdict.DecRef()
		case err := <-errCh:
			log.Warnf("kcap_read encountered an error: %v", err)
		case <-eokc:
			return kevents.RawPyObject()
		}
	}
}

func (f *filament) onInterval(fn *cpython.PyObject) {
	for {
		select {
		case <-f.tick.C:
			f.gil.Lock()
			r := fn.Call()
			if r != nil {
				r.DecRef()
			}
			if err := cpython.FetchErr(); err != nil {
				f.fnerrs <- err
			}
			f.gil.Unlock()
		case <-f.close:
		}
	}
}
