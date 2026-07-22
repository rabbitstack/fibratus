//go:build windows
// +build windows

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

package fs

import (
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/golang/groupcache/singleflight"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	directoryFile = 0x00000001 // file being created or opened is a directory file

	deviceCDROM      = 0x00000002
	deviceCDROMFs    = 0x00000003
	deviceController = 0x00000004
	deviceDatalink   = 0x00000005
	deviceDFS        = 0x00000006
	deviceDisk       = 0x00000007
	deviceDiskFs     = 0x00000008

	devMailslot  = 0x0000000c
	devNamedPipe = 0x00000011

	devConsole = 0x00000050
)

// metadataStoreQueueSize is the capacity of the async request channel.
const metadataStoreQueueSize = 1500

var fsMetadataAsyncRequestDrops = expvar.NewInt("fs.metadata.async.request.drops")

var fsMetadataCount = expvar.NewInt("fs.metadata.count")

var fsMetadataFileParseErrors = expvar.NewMap("fs.metadata.file.parse.errors")

var fsMetadataCacheHits = expvar.NewInt("fs.metadata.cache.hits")

var fsMetadataCacheMisses = expvar.NewInt("fs.metadata.cache.misses")

var fsMetadataEvictions = expvar.NewInt("fs.metadata.evictions")

// ErrSkippedFile signals the file processing is skipped.
var ErrSkippedFile = func(path string) error { return fmt.Errorf("skipped file: %s", path) }

var metadataStore *FileMetadataStore
var onceMetadataStore sync.Once

// metadataTTL is the maximum age of an untouched cache entry before the GC evicts it.
var metadataTTL = 10 * time.Minute

// windowsUpdateWildcards lists system directories commonly touched during
// updates, servicing, recovery, and component store operations.
// Excluded from metastore because they generate a lot of legitimate file
// activity.
type windowsUpdateWildcards []string

func (w *windowsUpdateWildcards) Accept(path string) bool {
	for _, wc := range *w {
		if wildcard.Match(wc, path, false) {
			return true
		}
	}
	return false
}

// moduleWildcards accepts well-known system executable or DLL paths.
type moduleWildcards map[string]struct{}

var sysroot string
var sysrootOnce sync.Once

func (w *moduleWildcards) Accept(path string) bool {
	sysrootOnce.Do(func() {
		sysroot = os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = os.Getenv("SYSTEMROOT")
		}
		if sysroot == "" {
			sysroot = "C:\\Windows"
		}
	})

	n := strings.ToLower(filepath.Base(path))
	_, ok := (*w)[n]
	if !ok {
		return false
	}

	return wildcard.Match(filepath.Join(sysroot, "System32", n), path, false) ||
		wildcard.Match(filepath.Join(sysroot, "Syswow64", n), path, false)
}

// FileInfo represents file metadata.
type FileInfo struct {
	IsExecutable bool
	IsDLL        bool
	IsDriver     bool
	IsDotnet     bool

	// accessed is updated on every cache lookup to drive TTL-based eviction.
	accessed atomic.Int64
}

func (f *FileInfo) keepalive() {
	f.accessed.Store(time.Now().UnixNano())
}

func (f *FileInfo) lastAccessed() time.Time {
	return time.Unix(0, f.accessed.Load())
}

type Request struct {
	Path     string
	Response chan *FileInfo
}

func GetMetadataStore() *FileMetadataStore {
	onceMetadataStore.Do(func() {
		metadataStore = newFileMetadataStore()
	})

	return metadataStore
}

// FileMetadataStore contains metainfo of PE files derived
// from file creation or DLL loading. Metadata store is
// invalidated on various signals such as file overwriting
// deletion or renaming.
//
// Metadata resolution is asynchronous. File and module events
// insert a pending entry immediately and enqueue a worker job.
type FileMetadataStore struct {
	mux   sync.RWMutex
	files map[string]*FileInfo

	requests chan Request

	stop  chan struct{}
	group singleflight.Group

	purger *time.Ticker

	windowsUpdateWildcards windowsUpdateWildcards
	wellKnownDLLs          moduleWildcards
	wellKnownExecutables   moduleWildcards
}

func newFileMetadataStore() *FileMetadataStore {
	s := &FileMetadataStore{
		files:    make(map[string]*FileInfo, 1024),
		requests: make(chan Request, metadataStoreQueueSize),
		stop:     make(chan struct{}),
		purger:   time.NewTicker(time.Minute),
		windowsUpdateWildcards: []string{
			`?:\$winreagent\scratch\*`,
			`?:\windows\winsxs\*`,
			`?:\windows\cbstemp\*`,
			`?:\windows\softwaredistribution\*`,
		},
		wellKnownDLLs: map[string]struct{}{
			"ntdll.dll":            {},
			"kernel32.dll":         {},
			"kernelbase.dll":       {},
			"kernel.appcore.dll":   {},
			"user32.dll":           {},
			"gdi32.dll":            {},
			"gdi32full.dll":        {},
			"advapi32.dll":         {},
			"msvcrt.dll":           {},
			"msvcp_win.dll":        {},
			"sechost.dll":          {},
			"rpcrt4.dll":           {},
			"combase.dll":          {},
			"ucrtbase.dll":         {},
			"win32u.dll":           {},
			"bcryptprimitives.dll": {},
			"ole32.dll":            {},
			"oleacc.dll":           {},
			"oleaut32.dll":         {},
			"shell32.dll":          {},
			"shlwapi.dll":          {},
			"shcore.dll":           {},
			"imm32.dll":            {},
			"ntmarta.dll":          {},
			"setupapi.dll":         {},
			"crypt32.dll":          {},
			"cryptbase.dll":        {},
			"bcrypt.dll":           {},
			"ws2_32.dll":           {},
			"wintrust.dll":         {},
			"netapi32.dll":         {},
			"powrprof.dll":         {},
			"psapi.dll":            {},
			"userenv.dll":          {},
			"profapi.dll":          {},
			"clbcatq.dll":          {},
			"windows.storage.dll":  {},
			"uxtheme.dll":          {},
			"dwmapi.dll":           {},
			"mscoree.dll":          {},
			"wintypes.dll":         {},
		},
		wellKnownExecutables: map[string]struct{}{
			// core OS / boot processes
			"smss.exe":     {},
			"csrss.exe":    {},
			"wininit.exe":  {},
			"winlogon.exe": {},
			"services.exe": {},
			"lsass.exe":    {},
			"svchost.exe":  {},
			"lsm.exe":      {},

			// desktop / shell
			"explorer.exe":                {},
			"dwm.exe":                     {},
			"sihost.exe":                  {},
			"taskhostw.exe":               {},
			"fontdrvhost.exe":             {},
			"ctfmon.exe":                  {},
			"shellexperiencehost.exe":     {},
			"startmenuexperiencehost.exe": {},
			"searchhost.exe":              {},
			"searchapp.exe":               {},
			"searchindexer.exe":           {},

			// common subsystem / broker processes
			"runtimebroker.exe":      {},
			"dllhost.exe":            {},
			"conhost.exe":            {},
			"wmiprvse.exe":           {},
			"spoolsv.exe":            {},
			"taskeng.exe":            {},
			"taskhost.exe":           {},
			"backgroundtaskhost.exe": {},

			// security / update related
			"smartscreen.exe":           {},
			"securityhealthservice.exe": {},
			"securityhealthsystray.exe": {},
			"msmpeng.exe":               {},
			"nissrv.exe":                {},
			"mpcmdrun.exe":              {},
			"trustedinstaller.exe":      {},
			"tiworker.exe":              {},
			"wuauclt.exe":               {},
			"usoclient.exe":             {},

			// remote/session infra
			"logonui.exe":  {},
			"userinit.exe": {},
		},
	}

	const numWorkers = 6
	for range numWorkers {
		go s.runWorker()
	}

	go s.runGC()

	return s
}

// DoRequest submits a file meta request and blocks until the result is ready.
// Use this when the caller must make an allow/deny decision such as
// in the field accessors.
func (s *FileMetadataStore) DoRequest(path string) *FileInfo {
	p := s.normalizePath(path)
	if f := s.get(p); f != nil {
		return f
	}

	if s.windowsUpdateWildcards.Accept(p) {
		return nil
	}

	if s.wellKnownDLLs.Accept(p) {
		s.addDLL(p)
		return s.get(p)
	}
	if s.wellKnownExecutables.Accept(p) {
		s.addExecutable(p)
		return s.get(p)
	}

	ch := make(chan *FileInfo, 1)
	select {
	case s.requests <- Request{Path: p, Response: ch}:
	default:
		// queue full: fall back to inline check rather than
		// dropping a decision that has a security consequence.
		return s.getOrParse(p)
	}
	r := <-ch
	return r
}

func (s *FileMetadataStore) DoRequestAsync(path string) {
	p := s.normalizePath(path)
	if s.contains(p) {
		return
	}

	if s.windowsUpdateWildcards.Accept(p) {
		return
	}

	if s.wellKnownDLLs.Accept(p) {
		s.addDLL(p)
		return
	}
	if s.wellKnownExecutables.Accept(p) {
		s.addExecutable(p)
		return
	}

	select {
	case s.requests <- Request{Path: p}:
	default:
		// queue is full
		fsMetadataAsyncRequestDrops.Add(1)
	}
}

func (s *FileMetadataStore) Close() {
	s.purger.Stop()
	close(s.stop)
}

func (s *FileMetadataStore) AddFile(path string, f *FileInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()
	fsMetadataCount.Add(1)
	s.files[path] = f
}

func (s *FileMetadataStore) RemoveFile(path string) {
	p := s.normalizePath(path)
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.files, p)
	fsMetadataCount.Add(-1)
}

func (s *FileMetadataStore) runWorker() {
	for {
		select {
		case r := <-s.requests:
			s.processRequest(r)
		case <-s.stop:
			return
		}
	}
}

// gc removes entries that have not been accessed within sigTTL.
// It reads the accessed timestamp via an atomic load, so it does not
// need to hold the write lock while computing ages.
func (s *FileMetadataStore) runGC() {
	for {
		select {
		case <-s.purger.C:
			s.gc()
		case <-s.stop:
			return
		}
	}
}

func (s *FileMetadataStore) gc() {
	now := time.Now()

	// collect stale files under a read lock to minimize write-lock hold time
	s.mux.RLock()
	var paths []string
	for path, file := range s.files {
		if now.Sub(file.lastAccessed()) > metadataTTL {
			paths = append(paths, path)
		}
	}
	s.mux.RUnlock()

	if len(paths) == 0 {
		return
	}

	s.mux.Lock()
	for _, path := range paths {
		file := s.files[path]
		// re-check under the write lock: the entry may have been
		// refreshed between the RUnlock above and this Lock
		if file != nil && now.Sub(file.lastAccessed()) > metadataTTL {
			log.Debugf("evicting file metadata for %s", path)
			fsMetadataCount.Add(-1)
			fsMetadataEvictions.Add(1)
			delete(s.files, path)
		}
	}
	s.mux.Unlock()
}

func (s *FileMetadataStore) processRequest(r Request) {
	f := s.getOrParse(r.Path)
	if r.Response != nil {
		r.Response <- f
	}
}

func (s *FileMetadataStore) contains(path string) bool {
	return s.get(path) != nil
}

func (s *FileMetadataStore) addDLL(path string) {
	f := &FileInfo{IsDLL: true}
	s.AddFile(path, f)
}

func (s *FileMetadataStore) addExecutable(path string) {
	f := &FileInfo{IsExecutable: true}
	s.AddFile(path, f)
}

func (s *FileMetadataStore) get(path string) *FileInfo {
	s.mux.RLock()
	f := s.files[path]
	s.mux.RUnlock()
	if f != nil {
		fsMetadataCacheHits.Add(1)
		f.keepalive()
	}
	return f
}

func (s *FileMetadataStore) getOrParse(path string) *FileInfo {
	if f := s.get(path); f != nil {
		return f
	}

	v, err := s.group.Do(path, func() (any, error) {
		pe, err := s.parsePE(path)
		if err != nil {
			return nil, err
		}
		return pe, nil
	})

	if err != nil {
		return nil
	}

	p := v.(*pe.PE)

	f := &FileInfo{}
	f.keepalive()
	f.IsDLL, f.IsDriver, f.IsExecutable, f.IsDotnet = p.IsDLL, p.IsDriver, p.IsExecutable, p.IsDotnet
	s.AddFile(path, f)
	fsMetadataCacheMisses.Add(1)

	return f
}

func (s *FileMetadataStore) parsePE(path string) (*pe.PE, error) {
	const size = 8 * 1024 * 1024 // 8MB
	data, err := sys.ReadFile(path, size, time.Millisecond*500)
	if err != nil {
		fsMetadataFileParseErrors.Add(err.Error(), 1)
		return nil, err
	}

	pe, err := pe.ParseBytes(data, pe.WithSections(), pe.WithSymbols(), pe.WithCLR())
	if err != nil {
		fsMetadataFileParseErrors.Add(err.Error(), 1)
		return nil, err
	}

	return pe, err
}

func (s *FileMetadataStore) normalizePath(path string) string {
	return strings.ToLower(path)
}

// GetFileType returns the underlying file type. The opts parameter corresponds to the NtCreateFile CreateOptions argument
// that specifies the options to be applied when creating or opening the file.
func GetFileType(filename string, opts uint32) FileType {
	if filename == "" {
		return Other
	}
	// if the CreateOptions argument of the NtCreateFile syscall has been invoked
	// with the FILE_DIRECTORY_FILE flag, it is likely that the target file object
	// is a directory. We ensure that by calling the API function for checking whether
	// the path name is truly a directory
	if (opts&directoryFile) != 0 && sys.PathIsDirectory(filename) {
		return Directory
	}
	// FILE_DIRECTORY_FILE flag only gives us a hint on the CreateFile op outcome. If this flag is
	// not present in the argument but the file is a directory, we can apply some simple heuristics
	// like checking the extension/suffix, even though they are not bullet-proof
	if filename[:len(filename)-1] == "\\" || filepath.Ext(filename) == "" {
		return Directory
	}
	// non directory file can be a regular file, logical, virtual or physical device or a volume.
	// If the filename doesn't start with a drive letter it's probably not a regular
	// file since we already have mapped the DOS name to drive letter
	if !strings.HasPrefix(filename, "\\Device") {
		return Regular
	}
	// if the filename contains the HardiskVolume string then we assume it is a file. This
	// could happen if we fail to resolve the DOS name
	if strings.HasPrefix(filename, "\\Device\\HarddiskVolume") {
		return Regular
	}
	// logical, virtual, physical device or a volume
	// obtain the device type that is linked to this file object
	return getFileTypeFromVolumeInfo(filename)
}

// queryVolumeCalls represents the number of times the query volume function was called
var queryVolumeCalls = expvar.NewInt("file.query.volume.info.calls")

func getFileTypeFromVolumeInfo(filename string) FileType {
	f, err := os.Open(filename)
	if err != nil {
		return Other
	}
	defer f.Close()

	queryVolumeCalls.Add(1)

	var (
		iosb windows.IO_STATUS_BLOCK
		dev  sys.FileFsDeviceInformation
	)
	err = sys.NtQueryVolumeInformationFile(
		windows.Handle(f.Fd()),
		&iosb,
		uintptr(unsafe.Pointer(&dev)),
		uint32(unsafe.Sizeof(dev)),
		sys.FileFsDeviceInformationClass,
	)
	if err != nil {
		return Other
	}
	switch dev.Type {
	case deviceCDROM, deviceCDROMFs, deviceController,
		deviceDatalink, deviceDFS, deviceDisk, deviceDiskFs:
		if sys.PathIsDirectory(filename) {
			return Directory
		}
		return Regular
	case devConsole:
		return Console
	case devMailslot:
		return Mailslot
	case devNamedPipe:
		return Pipe
	default:
		return Other
	}
}
