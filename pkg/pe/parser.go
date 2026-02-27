/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package pe

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/format"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	peparser "github.com/saferwall/pe"
	peparserlog "github.com/saferwall/pe/log"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	// MaxHeaderSize specifies the maximum size of the PE header
	MaxHeaderSize = uint(os.Getpagesize())
	// MinHeaderSize denotes the minimal valid PE header size
	MinHeaderSize = uint(0x100)
	// ErrEmptyVArea represents the error which is returned if the VA area couldn't be read
	ErrEmptyVArea = errors.New("va memory area is empty")

	skippedImages               = expvar.NewInt("pe.skipped.images")
	directoryParseErrors        = expvar.NewInt("pe.directory.parse.errors")
	versionResourcesParseErrors = expvar.NewInt("pe.version.resources.parse.errors")
	imphashErrors               = expvar.NewInt("pe.imphash.errors")
	parserWarnings              = expvar.NewMap("pe.parser.warnings")
)

type opts struct {
	parseSymbols   bool
	parseSections  bool
	parseResources bool
	parseSecurity  bool
	parseCLR       bool
	parseExports   bool
	sectionEntropy bool
	sectionMD5     bool
	calcImphash    bool
	excludedImages []string
}

func (o opts) isImageExcluded(path string) bool {
	for _, img := range o.excludedImages {
		if strings.EqualFold(img, filepath.Base(path)) {
			skippedImages.Add(1)
			return true
		}
	}
	return false
}

// Option represents the option type for the PE parser.
type Option func(o *opts)

// WithExcludedImages provides a list of image paths for
// which the parsing is skipped.
func WithExcludedImages(images []string) Option {
	return func(o *opts) {
		o.excludedImages = images
	}
}

// WithSymbols indicates import directory is parsed for imported symbols.
func WithSymbols() Option {
	return func(o *opts) {
		o.parseSymbols = true
	}
}

// WithSections indicates section header is parsed.
func WithSections() Option {
	return func(o *opts) {
		o.parseSections = true
	}
}

// WithExports indicates if the export directory is parsed.
func WithExports() Option {
	return func(o *opts) {
		o.parseExports = true
	}
}

// WithSectionEntropy indicates if entropy is calculated for available sections.
func WithSectionEntropy() Option {
	return func(o *opts) {
		o.sectionEntropy = true
	}
}

// WithSectionMD5 indicates if MD5 hash is calculated for available sections.
func WithSectionMD5() Option {
	return func(o *opts) {
		o.sectionMD5 = true
	}
}

// WithVersionResources indicates if version resources are parsed from the resource directory.
func WithVersionResources() Option {
	return func(o *opts) {
		o.parseResources = true
	}
}

// WithSecurity indicates if the security directory is parsed to extract signature information
// like certificates or Authenticode hashes.
func WithSecurity() Option {
	return func(o *opts) {
		o.parseSecurity = true
	}
}

// WithImphash indicates if the import hash (imphash) is calculated as part of PE parsing.
func WithImphash() Option {
	return func(o *opts) {
		o.calcImphash = true
	}
}

// WithCLR indicates if CLR (Common Language Runtime) header is parsed.
func WithCLR() Option {
	return func(o *opts) {
		o.parseCLR = true
	}
}

// ParseFile parses the PE given the file system path and parser options.
func ParseFile(path string, opts ...Option) (*PE, error) {
	return parse(path, nil, opts...)
}

// ParseFileWithConfig parses the PE given the file system path and the config
// which is usually read from the YAML file. Config flags are converted to parser
// options.
func ParseFileWithConfig(path string, config Config) (*PE, error) {
	if !config.Enabled {
		return nil, nil
	}
	var opts []Option
	if len(config.ExcludedImages) > 0 {
		opts = append(opts, WithExcludedImages(config.ExcludedImages))
	}
	if config.ReadSections {
		opts = append(opts, WithSections())
	}
	if config.ReadSymbols {
		opts = append(opts, WithSymbols())
	}
	if config.ReadResources {
		opts = append(opts, WithVersionResources())
	}
	return ParseFile(path, opts...)
}

// ParseBytes tries to parse the PE from the given byte slice and parser options.
func ParseBytes(data []byte, opts ...Option) (*PE, error) {
	if len(data) == 0 || va.Zeroed(data) {
		return nil, ErrEmptyVArea
	}
	return parse("", data, opts...)
}

// ParseMem parses the in-memory layout of the PE header for the
// specified process and base address. If change protection parameter
// is set to true, this method will attempt to change region protection
// if the region is marked as inaccessible.
func ParseMem(pid uint32, base uintptr, changeProtection bool, opts ...Option) (*PE, error) {
	access := windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
	if changeProtection {
		access |= windows.PROCESS_VM_OPERATION
	}
	process, err := windows.OpenProcess(uint32(access), false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.Close(process)
	area := va.ReadArea(process, base, MaxHeaderSize, MinHeaderSize, changeProtection)
	return ParseBytes(area, opts...)
}

func newParserOpts(opts opts) *peparser.Options {
	return &peparser.Options{
		DisableCertValidation:     true,
		OmitIATDirectory:          true,
		OmitSecurityDirectory:     !opts.parseSecurity,
		OmitExceptionDirectory:    true,
		OmitTLSDirectory:          true,
		OmitCLRHeaderDirectory:    !opts.parseCLR,
		OmitCLRMetadata:           true,
		OmitDelayImportDirectory:  true,
		OmitBoundImportDirectory:  true,
		OmitArchitectureDirectory: true,
		OmitDebugDirectory:        true,
		OmitRelocDirectory:        true,
		OmitResourceDirectory:     !opts.parseResources,
		OmitImportDirectory:       !opts.parseSymbols && !opts.calcImphash,
		OmitExportDirectory:       !opts.parseExports,
		OmitLoadConfigDirectory:   true,
		OmitGlobalPtrDirectory:    true,
		SectionEntropy:            opts.sectionEntropy,
		Logger:                    &Logger{},
	}
}

// Logger is the adapter for routing PE package logs to logrus.
type Logger struct{}

func (l Logger) Log(level peparserlog.Level, keyvals ...interface{}) error {
	switch level {
	case peparserlog.LevelDebug:
		log.Debug(keyvals[1:]...)
	case peparserlog.LevelInfo:
		log.Info(keyvals[1:]...)
	case peparserlog.LevelWarn:
		parserWarnings.Add(fmt.Sprintf("%s", keyvals[1:]), 1)
	case peparserlog.LevelError, peparserlog.LevelFatal:
		log.Error(keyvals[1:]...)
	default:
		log.Info(keyvals[1:]...)
	}
	return nil
}

func parse(path string, data []byte, options ...Option) (*PE, error) {
	var opts opts
	for _, opt := range options {
		opt(&opts)
	}
	if opts.isImageExcluded(path) {
		return nil, nil
	}
	var pe *peparser.File
	var err error
	if data == nil {
		pe, err = peparser.New(path, newParserOpts(opts))
	} else {
		pe, err = peparser.NewBytes(data, newParserOpts(opts))
	}
	if err != nil {
		return nil, err
	}
	defer pe.Close()

	// parse the DOS header
	err = pe.ParseDOSHeader()
	if err != nil {
		return nil, err
	}

	// parse the NT header
	err = pe.ParseNTHeader()
	if err != nil {
		return nil, err
	}

	timestamp := pe.NtHeader.FileHeader.TimeDateStamp
	linkTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Second * time.Duration(timestamp))
	p := &PE{
		NumberOfSections: pe.NtHeader.FileHeader.NumberOfSections,
		LinkTime:         linkTime,
		Symbols:          make([]string, 0),
		Imports:          make([]string, 0),
		Sections:         make([]Sec, 0),
		Exports:          make(map[uint32]string, 0),
		VersionResources: make(map[string]string),
		Is64:             pe.Is64,
		filename:         path,
		dosHeader:        pe.DOSHeader,
		ntHeader:         pe.NtHeader,
		sectionHeaders:   make([]peparser.ImageSectionHeader, 0),
	}

	switch pe.Is64 {
	case true:
		oh64 := pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader64)
		p.ImageBase = format.UintToHex(oh64.ImageBase)
		p.EntryPoint = format.UintToHex(uint64(oh64.AddressOfEntryPoint))
	case false:
		oh32 := pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
		p.ImageBase = format.UintToHex(uint64(oh32.ImageBase))
		p.EntryPoint = format.UintToHex(uint64(oh32.AddressOfEntryPoint))
	}

	// parse section header
	if opts.parseSections || opts.parseResources || opts.parseCLR {
		err = pe.ParseSectionHeader()
		if err != nil {
			return nil, err
		}
	}
	for _, section := range pe.Sections {
		sec := Sec{
			Name: section.String(),
			Size: section.Header.VirtualSize,
		}
		if section.Entropy != nil {
			sec.Entropy = *section.Entropy
		}
		if opts.sectionMD5 {
			sum := md5.Sum(section.Data(0, 0, pe))
			sec.Md5 = hex.EncodeToString(sum[:])
		}
		p.Sections = append(p.Sections, sec)
	}

	// initialize raw section headers
	for _, sec := range pe.Sections {
		p.sectionHeaders = append(p.sectionHeaders, sec.Header)
	}

	if opts.parseSymbols || opts.parseResources || opts.parseSecurity ||
		opts.calcImphash || opts.parseCLR || opts.parseExports {
		// parse data directories
		err = pe.ParseDataDirectories()
		if err != nil {
			directoryParseErrors.Add(1)
		}
	}

	// add imported symbols
	for _, imp := range pe.Imports {
		p.addImport(imp.Name)
		for _, fun := range imp.Functions {
			p.addSymbol(fun.Name)
		}
	}
	p.NumberOfSymbols = uint32(len(p.Symbols))

	// add exports
	for _, exp := range pe.Export.Functions {
		if exp.Name != "" {
			p.Exports[exp.FunctionRVA] = exp.Name
		} else if exp.Forwarder != "" {
			p.Exports[exp.ForwarderRVA] = exp.Forwarder
		} else {
			p.Exports[exp.FunctionRVA] = fmt.Sprintf("Ordinal%d", exp.Ordinal)
		}
	}

	if opts.parseResources {
		// parse version resources
		p.VersionResources, err = pe.ParseVersionResources()
		if err != nil {
			versionResourcesParseErrors.Add(1)
		}
	}

	// parse certificate info
	if opts.parseSecurity {
		p.IsSigned = pe.IsSigned
		if pe.HasCertificate && len(pe.Certificates.Certificates) > 0 {
			cert := pe.Certificates.Certificates[0]
			p.Cert = &sys.Cert{
				Issuer:       cert.Info.Issuer,
				Subject:      cert.Info.Subject,
				NotBefore:    cert.Info.NotBefore,
				NotAfter:     cert.Info.NotAfter,
				SerialNumber: cert.Info.SerialNumber,
			}
		}
	}

	// calculate imphash
	if opts.calcImphash {
		p.Imphash, err = pe.ImpHash()
		if err != nil {
			imphashErrors.Add(1)
		}
	}

	p.IsDLL = pe.IsDLL()
	p.IsDriver = p.isDriver()
	p.IsExecutable = pe.IsEXE()
	p.IsDotnet = pe.HasCLR
	p.Anomalies = pe.Anomalies

	return p, nil
}

// isDriver determines if the PE is a Windows driver. This method is inherited
// from the saferwall parser with the imports defensive check removed as some
// driver samples may not contain an import directory, but section names may
// reveal the PE is a kernel driver.
func (pe *PE) isDriver() bool {
	// Prevent false positives such as ntdll.dll
	// because it has the PAGE section which is
	// driver-typical
	if pe.IsDLL {
		return false
	}
	// DIRECTORY_ENTRY_IMPORT may exist, although it may be empty.
	// If it imports from "ntoskrnl.exe" or other kernel components it should
	// be a driver.
	systemDLLs := []string{"ntoskrnl.exe", "hal.dll", "ndis.sys",
		"bootvid.dll", "kdcom.dll"}
	for _, imp := range pe.Imports {
		for _, dll := range systemDLLs {
			if strings.ToLower(imp) == dll {
				return true
			}
		}
	}

	// If still we couldn't tell, check common driver section with combination
	// of IMAGE_SUBSYSTEM_NATIVE or IMAGE_SUBSYSTEM_NATIVE_WINDOWS.
	subsystem := peparser.ImageOptionalHeaderSubsystemType(0)
	oh32 := peparser.ImageOptionalHeader32{}
	oh64 := peparser.ImageOptionalHeader64{}
	switch pe.Is64 {
	case true:
		oh64 = pe.ntHeader.OptionalHeader.(peparser.ImageOptionalHeader64)
		subsystem = oh64.Subsystem
	case false:
		oh32 = pe.ntHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
		subsystem = oh32.Subsystem
	}
	commonDriverSectionNames := []string{"page", "paged", "nonpage", "init"}
	for _, section := range pe.Sections {
		s := strings.ToLower(section.Name)
		for _, driverSection := range commonDriverSectionNames {
			if s == driverSection &&
				(subsystem&peparser.ImageSubsystemNativeWindows != 0 ||
					subsystem&peparser.ImageSubsystemNative != 0) {
				return true
			}
		}
	}
	return false
}
