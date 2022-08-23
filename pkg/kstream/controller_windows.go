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

package kstream

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	// maxBufferSize specifies the maximum buffer size for event tracing session buffer
	maxBufferSize = 1024
	// etwMaxLoggersPath is the registry subkey that contains ETW logger preferences
	etwMaxLoggersPath = `SYSTEM\CurrentControlSet\Control\WMI`
	// etwMaxLoggersValue is the registry value that dictates the maximum number of loggers. Default value is 64 on most systems
	etwMaxLoggersValue = "EtwMaxLoggers"
	maxStringLen       = 1024
)

// for testing purposes
var (
	startTrace   = etw.StartTrace
	controlTrace = etw.ControlTrace
	enableTrace  = etw.EnableTrace
)

// TraceSession stores metadata of the initiated tracing session.
type TraceSession struct {
	Handle etw.TraceHandle
	Name   string
	GUID   syscall.GUID
}

// TraceProvider describes the ETW provider metainfo. The provider
// acts as a source of events that are published to the tracing
// session.
type TraceProvider struct {
	TraceName string       // trace name
	GUID      syscall.GUID // provider GUID
	Keywords  uint32       // enabled keywords
	Enabled   bool         // whether the provider is enabled
}

// IsKernelLogger determines if this provider is the NT Kernel Logger.
func (p TraceProvider) IsKernelLogger() bool {
	return p.GUID == etw.KernelTraceControlGUID
}

var providers = []TraceProvider{
	{
		// core system events
		etw.KernelLoggerSession,
		etw.KernelTraceControlGUID,
		0x0, // no keywords
		true,
	},
	{
		// provides a source of events for constructing the state of opened file objects
		etw.KernelLoggerRundownSession,
		etw.KernelRundownGUID,
		0x10, // file rundown events
		true,
	},
	{
		// supplies the `OpenProcess` and `OpenThread` events
		etw.KernelAuditAPICallsSession,
		etw.KernelAuditAPICallsGUID,
		0x0, // no keywords, so we accept all events
		true,
	},
}

// KtraceController is responsible for managing the life cycle of the tracing sessions.
type KtraceController interface {
	// StartKtrace starts configured tracing sessions.
	StartKtrace() error
	// CloseKtrace stops currently running tracing sessions.
	CloseKtrace() error
}

type ktraceController struct {
	// kstreamConfig stores kernel stream-specific settings
	kstreamConfig config.KstreamConfig
	// traces contain initiated tracing sessions
	traces map[string]TraceSession
}

// NewKtraceController spins up a new instance of kernel trace controller.
func NewKtraceController(kstreamConfig config.KstreamConfig) KtraceController {
	controller := &ktraceController{
		kstreamConfig: kstreamConfig,
		traces:        make(map[string]TraceSession, 0),
	}
	return controller
}

// StartKtrace starts configured tracing sessions. User has the ability to disable
// a specific subset of collected kernel events, even though by default most events
// are forwarded from the provider. Flags are only valid in context of the NT Kernel
// Logger sessions. On the contrary, keywords can only be used on the non-NT Kernel
// Logger tracing sessions.
func (k *ktraceController) StartKtrace() error {
	// at least process events have to be enabled
	// for the purpose of building the state machine
	flags := etw.Process
	if k.kstreamConfig.EnableThreadKevents {
		flags |= etw.Thread
	}
	if k.kstreamConfig.EnableImageKevents {
		flags |= etw.ImageLoad
	}
	if k.kstreamConfig.EnableNetKevents {
		flags |= etw.NetTCPIP
	}
	if k.kstreamConfig.EnableRegistryKevents {
		flags |= etw.Registry
	}
	if k.kstreamConfig.EnableFileIOKevents {
		flags |= etw.DiskFileIO | etw.FileIO | etw.FileIOInit
	}

	bufferSize := k.kstreamConfig.BufferSize
	if bufferSize > maxBufferSize {
		bufferSize = maxBufferSize
	}
	// validate min/max buffers. The minimal
	// number of buffers is 2 per CPU logical core
	minBuffers := k.kstreamConfig.MinBuffers
	if minBuffers < uint32(runtime.NumCPU()*2) {
		minBuffers = uint32(runtime.NumCPU() * 2)
	}
	maxBuffers := k.kstreamConfig.MaxBuffers
	maxBuffersAllowed := minBuffers + 20
	if maxBuffers > maxBuffersAllowed {
		maxBuffers = maxBuffersAllowed
	}
	if minBuffers > maxBuffers {
		minBuffers = maxBuffers
	}

	flushTimer := k.kstreamConfig.FlushTimer
	if flushTimer < time.Second {
		flushTimer = time.Second
	}

	for _, prov := range providers {
		if !prov.Enabled {
			log.Warnf("provider for trace [%s] is disabled", prov.TraceName)
			continue
		}
		props := &etw.EventTraceProperties{
			Wnode: etw.WnodeHeader{
				BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
				Flags:      etw.WnodeTraceFlagGUID,
			},
			LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
			LogFileNameOffset: 0,
			BufferSize:        bufferSize,
			LogFileMode:       etw.ProcessTraceModeRealtime,
			MinimumBuffers:    minBuffers,
			MaximumBuffers:    maxBuffers,
			FlushTimer:        uint32(flushTimer.Seconds()),
		}
		if prov.IsKernelLogger() {
			props.EnableFlags = flags
			props.Wnode.GUID = prov.GUID
			log.Debugf("starting kernel trace with %q event flags", flags)
		}
		traceName := prov.TraceName

		handle, err := startTrace(
			traceName,
			props,
		)
		log.Debugf("starting trace [%s]", traceName)

		if err == nil {
			if !handle.IsValid() {
				return kerrors.ErrInvalidTrace
			}
			if prov.IsKernelLogger() {
				handleCopy := handle
				// poorly documented ETW feature that allows for enabling an extended set of
				// kernel event tracing flags. According to the MSDN documentation, aside from
				// invoking `EventTraceProperties` function to enable object manager tracking
				// the `EventTraceProperties` structure's `EnableFlags` member needs to be set to PERF_OB_HANDLE (0x80000040).
				// This actually results in an erroneous trace start. The documentation neither specifies how the function
				// should be called (group mask array with its 4th element set to 0x80000040).
				sysTraceFlags := make([]etw.EventTraceFlags, 8)
				// when we call the`TraceSetInformation` with event empty group mask reserved for the
				// flags that are bitvectored into `EventTraceProperties` structure's `EnableFlags` field,
				// it will trigger the arrival of rundown events including open file objects and
				// registry keys that are very valuable for us to construct the initial snapshot of
				// these system resources and let us build the event's context
				if err := etw.SetTraceInformation(handle, etw.TraceSystemTraceEnableFlagsInfo, sysTraceFlags); err != nil {
					log.Warn(err)
				}
				sysTraceFlags[0] = flags
				// enable object manager tracking
				if k.kstreamConfig.EnableHandleKevents {
					sysTraceFlags[4] = etw.Handle
				}
				// call again to enable all kernel events. Just to recap. The first call to `TraceSetInformation` with empty
				// group masks activates rundown events, while this second call enables the rest of the kernel events specified in flags.
				if err := etw.SetTraceInformation(handle, etw.TraceSystemTraceEnableFlagsInfo, sysTraceFlags); err != nil {
					log.Warnf("unable to set trace information: %v", err)
				}
				k.insertTrace(traceName, handleCopy, prov.GUID)
			} else {
				// enable the specified trace provider
				if err := enableTrace(prov.GUID, handle, prov.Keywords); err != nil {
					return fmt.Errorf("unable to activate %s provider: %v", traceName, err)
				}
				k.insertTrace(traceName, handle, prov.GUID)
			}
		}

		switch err {
		case kerrors.ErrTraceAlreadyRunning:
			if err := controlTrace(etw.TraceHandle(0), traceName, props, etw.Query); err == kerrors.ErrKsessionNotRunning {
				return kerrors.ErrCannotUpdateTrace
			}
			if err := controlTrace(etw.TraceHandle(0), traceName, props, etw.Stop); err != nil {
				return kerrors.ErrStopTrace
			}

			time.Sleep(time.Millisecond * 100)
			props := &etw.EventTraceProperties{
				Wnode: etw.WnodeHeader{
					BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
					Flags:      etw.WnodeTraceFlagGUID,
				},
				LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
				LogFileNameOffset: 0,
				BufferSize:        bufferSize,
				LogFileMode:       etw.ProcessTraceModeRealtime,
				MinimumBuffers:    minBuffers,
				MaximumBuffers:    maxBuffers,
				FlushTimer:        uint32(flushTimer.Seconds()),
			}
			if prov.IsKernelLogger() {
				props.EnableFlags = flags
				props.Wnode.GUID = prov.GUID
			}
			handle, err := startTrace(
				traceName,
				props,
			)
			if err != nil {
				return kerrors.ErrRestartTrace
			}
			if !handle.IsValid() {
				return kerrors.ErrInvalidTrace
			}
			if prov.IsKernelLogger() {
				handleCopy := handle

				sysTraceFlags := make([]etw.EventTraceFlags, 8)
				if err := etw.SetTraceInformation(handle, etw.TraceSystemTraceEnableFlagsInfo, sysTraceFlags); err != nil {
					log.Warn(err)
				}
				sysTraceFlags[0] = flags
				// enable object manager tracking
				if k.kstreamConfig.EnableHandleKevents {
					sysTraceFlags[4] = etw.Handle
				}
				// call again to enable all kernel events. Just to recap. The first call to `TraceSetInformation` with empty
				// group masks activates rundown events, while this second call enables the rest of the kernel events specified in flags.
				if err := etw.SetTraceInformation(handle, etw.TraceSystemTraceEnableFlagsInfo, sysTraceFlags); err != nil {
					log.Warnf("unable to set trace information: %v", err)
				}
				k.insertTrace(traceName, handleCopy, prov.GUID)
			} else {
				if err := enableTrace(prov.GUID, handle, prov.Keywords); err != nil {
					return fmt.Errorf("unable to activate %s provider: %v", traceName, err)
				}
				k.insertTrace(traceName, handle, prov.GUID)
			}
		case kerrors.ErrTraceNoSysResources:
			// get the number of maximum allowed loggers from registry
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, etwMaxLoggersPath, registry.QUERY_VALUE)
			if err != nil {
				return err
			}
			v, _, err := key.GetIntegerValue(etwMaxLoggersValue)
			if err != nil {
				_ = key.Close()
				return err
			}
			_ = key.Close()
			return fmt.Errorf(`the limit for logging sessions on your system is %d. Please consider increasing this number `+
				`by editing HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers key in registry. `+
				`Permissible values are 32 through 256 inclusive, and a reboot is required for any change to take effect`, v)
		default:
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CloseKtrace stops currently running trace sessions.
func (k *ktraceController) CloseKtrace() error {
	for _, trace := range k.traces {
		props := &etw.EventTraceProperties{
			Wnode: etw.WnodeHeader{
				BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
				GUID:       trace.GUID,
			},
			LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
			LogFileNameOffset: 0,
		}
		if err := controlTrace(etw.TraceHandle(0), trace.Name, props, etw.Flush); err != nil {
			log.Warnf("couldn't flush trace session for [%s]: %v", trace.Name, err)
		}
		time.Sleep(time.Millisecond * 50)
		if err := controlTrace(etw.TraceHandle(0), trace.Name, props, etw.Stop); err != nil {
			log.Warnf("couldn't stop trace session for [%s]: %v", trace.Name, err)
		}
	}
	return nil
}

func (k *ktraceController) insertTrace(name string, handle etw.TraceHandle, guid syscall.GUID) {
	trace := TraceSession{
		Handle: handle,
		Name:   name,
		GUID:   guid,
	}
	k.traces[name] = trace
}
