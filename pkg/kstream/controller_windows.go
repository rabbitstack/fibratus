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
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
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
	maxLoggerNameSize  = 128
	maxLogfileNameSize = 1024
	// maxTracePropsSize must make room for logger name and log file name
	maxTracePropsSize = 2 * (maxLoggerNameSize + maxLogfileNameSize)
)

// TraceSession stores metadata of the initiated tracing session.
type TraceSession struct {
	Handle etw.TraceHandle
	Name   string
	GUID   syscall.GUID
}

// IsKernelLogger determines if the session is tied to the NT Kernel Logger provider.
func (s TraceSession) IsKernelLogger() bool {
	return s.GUID == etw.KernelTraceControlGUID
}

// TraceProvider describes the ETW provider metainfo. The provider
// acts as a source of events that are published to the tracing
// session.
type TraceProvider struct {
	TraceName string       // trace name
	GUID      syscall.GUID // provider GUID
	Keywords  uint64       // enabled keywords
	Enabled   bool         // whether the provider is enabled
}

// IsKernelLogger determines if this provider is the NT Kernel Logger.
func (p TraceProvider) IsKernelLogger() bool {
	return p.GUID == etw.KernelTraceControlGUID
}

// KtraceController is responsible for managing the life cycle of the tracing sessions.
type KtraceController struct {
	// kstreamConfig stores kernel stream-specific settings
	kstreamConfig config.KstreamConfig
	// traces contains initiated tracing sessions
	traces map[string]TraceSession
	// providers contains a list of enabled ETW providers from
	// which the telemetry is collected
	providers []TraceProvider
}

// NewKtraceController spins up a new instance of the trace controller.
func NewKtraceController(kstreamConfig config.KstreamConfig) *KtraceController {
	providers := []TraceProvider{
		{
			// core system events
			etw.KernelLoggerSession,
			etw.KernelTraceControlGUID,
			0x0, // no keywords
			true,
		},
		{
			// supplies the `OpenProcess` and `OpenThread` events
			etw.KernelAuditAPICallsSession,
			etw.KernelAuditAPICallsGUID,
			0x0, // no keywords, so we accept all events
			kstreamConfig.EnableAuditAPIEvents,
		},
		{
			etw.AntimalwareEngineSession,
			etw.AntimalwareEngineGUID,
			0x0,
			kstreamConfig.EnableAntimalwareEngineEvents,
		},
	}
	controller := &KtraceController{
		kstreamConfig: kstreamConfig,
		traces:        make(map[string]TraceSession),
		providers:     providers,
	}
	return controller
}

// StartKtrace starts configured tracing sessions. User has the ability to disable
// a specific subset of collected kernel events, even though by default most events
// are forwarded from the provider. Flags are only valid in context of the NT Kernel
// Logger sessions. On the contrary, keywords can only be used on the non-NT Kernel
// Logger tracing sessions.
func (k *KtraceController) StartKtrace() error {
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
		minBuffers = maxBuffers - 20
	}

	flushTimer := k.kstreamConfig.FlushTimer
	if flushTimer < time.Second {
		flushTimer = time.Second
	}

	for _, prov := range k.providers {
		if !prov.Enabled {
			log.Warnf("provider for trace [%s] is disabled", prov.TraceName)
			continue
		}
		traceName := prov.TraceName
		if len(traceName) > maxLoggerNameSize {
			log.Warnf("trace name [%s] is too long", prov.TraceName)
			continue
		}
		props := etw.EventTraceProperties{
			Wnode: etw.WnodeHeader{
				BufferSize:    uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + maxTracePropsSize,
				Flags:         etw.WnodeTraceFlagGUID,
				ClientContext: 1, // QPC clock resolution
			},
			BufferSize:     bufferSize,
			LogFileMode:    etw.ProcessTraceModeRealtime,
			MinimumBuffers: minBuffers,
			MaximumBuffers: maxBuffers,
			FlushTimer:     uint32(flushTimer.Seconds()),
		}
		if prov.IsKernelLogger() {
			props.EnableFlags = flags
			props.Wnode.GUID = prov.GUID
			log.Debugf("starting kernel trace with %q event flags", flags)
		}

		handle, err := etw.StartTrace(
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
				// the `EventTraceProperties` structure's `EnableFlags` member needs to be set
				// to PERF_OB_HANDLE (0x80000040). This actually results in an erroneous trace start.
				// The documentation neither specifies how the function should be called, group mask
				// array with its 4th element set to 0x80000040.
				sysTraceFlags := make([]etw.EventTraceFlags, 8)
				// when we call the`TraceSetInformation` with event empty group mask reserved for the
				// flags that are bitvectored into `EventTraceProperties` structure's `EnableFlags` field,
				// it will trigger the arrival of rundown events including open file objects and
				// registry keys that are very valuable for us to construct the initial snapshot of
				// these system resources and let us build the event's context
				if err := etw.SetTraceSystemFlags(handleCopy, sysTraceFlags); err != nil {
					log.Warn(err)
				}
				sysTraceFlags[0] = flags
				// enable object manager tracking
				if k.kstreamConfig.EnableHandleKevents {
					sysTraceFlags[4] = etw.Handle
				}
				// call again to enable all kernel events. Just to recap. The first call to
				// `TraceSetInformation` with empty group masks activates rundown events,
				// while this second call enables the rest of the kernel events specified in flags.
				if err := etw.SetTraceSystemFlags(handleCopy, sysTraceFlags); err != nil {
					log.Warnf("unable to set trace information: %v", err)
				}
				k.insertTrace(traceName, handle, prov.GUID)
			} else {
				// enable the specified trace provider
				if err := etw.EnableTrace(prov.GUID, handle, prov.Keywords); err != nil {
					return fmt.Errorf("unable to activate %s provider: %v", traceName, err)
				}
				k.insertTrace(traceName, handle, prov.GUID)
			}
		}
		switch err {
		case kerrors.ErrTraceAlreadyRunning:
			log.Debugf("%s trace is already running. Trying to restart...", traceName)
			if err := etw.StopTrace(traceName, prov.GUID); err != nil {
				return multierror.Wrap(kerrors.ErrStopTrace, err)
			}
			time.Sleep(time.Millisecond * 100)
			props := etw.EventTraceProperties{
				Wnode: etw.WnodeHeader{
					BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + maxTracePropsSize,
					Flags:      etw.WnodeTraceFlagGUID,
				},
				BufferSize:     bufferSize,
				LogFileMode:    etw.ProcessTraceModeRealtime,
				MinimumBuffers: minBuffers,
				MaximumBuffers: maxBuffers,
				FlushTimer:     uint32(flushTimer.Seconds()),
			}
			if prov.IsKernelLogger() {
				props.EnableFlags = flags
				props.Wnode.GUID = prov.GUID
			}
			log.Debugf("restarting trace [%s]", traceName)
			handle, err := etw.StartTrace(
				traceName,
				props,
			)
			if err != nil {
				return multierror.Wrap(kerrors.ErrRestartTrace, err)
			}
			if !handle.IsValid() {
				return kerrors.ErrInvalidTrace
			}
			if prov.IsKernelLogger() {
				handleCopy := handle
				sysTraceFlags := make([]etw.EventTraceFlags, 8)
				if err := etw.SetTraceSystemFlags(handleCopy, sysTraceFlags); err != nil {
					log.Warn(err)
				}
				sysTraceFlags[0] = flags
				// enable object manager tracking
				if k.kstreamConfig.EnableHandleKevents {
					sysTraceFlags[4] = etw.Handle
				}
				// call again to enable all kernel events. Just to recap. The first call to `TraceSetInformation` with empty
				// group masks activates rundown events, while this second call enables the rest of the kernel events specified in flags.
				if err := etw.SetTraceSystemFlags(handleCopy, sysTraceFlags); err != nil {
					log.Warnf("unable to set trace information: %v", err)
				}
				k.insertTrace(traceName, handle, prov.GUID)
			} else {
				if err := etw.EnableTrace(prov.GUID, handle, prov.Keywords); err != nil {
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
func (k *KtraceController) CloseKtrace() error {
	for _, trace := range k.traces {
		if !trace.Handle.IsValid() {
			continue
		}
		traceName := trace.Name
		if err := etw.FlushTrace(traceName, trace.GUID); err != nil {
			log.Warnf("couldn't flush trace session for [%s]: %v", traceName, err)
		}
		time.Sleep(time.Millisecond * 150)
		if err := etw.StopTrace(traceName, trace.GUID); err != nil {
			log.Warnf("couldn't stop trace session for [%s]: %v", traceName, err)
		}
	}
	return nil
}

func (k *KtraceController) Traces() map[string]TraceSession {
	return k.traces
}

func (k *KtraceController) insertTrace(name string, handle etw.TraceHandle, guid syscall.GUID) {
	trace := TraceSession{
		Handle: handle,
		Name:   name,
		GUID:   guid,
	}
	k.traces[name] = trace
}
