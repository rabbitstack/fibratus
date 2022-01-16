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
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

const (
	ktraceSession   = etw.KernelLoggerSession
	krundownSession = etw.KernelLoggerRundownSession
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

// KtraceController is responsible for managing the life cycle of the kernel traces.
type KtraceController interface {
	// StartKtrace starts a new kernel tracing session.
	StartKtrace() error
	// CloseKtrace stops currently running kernel trace session.
	CloseKtrace() error
	// StartKtraceRundown initiates the kernel logger rundown session that will enumerate open file objects
	// we can use to match file names in file system kernel events.
	StartKtraceRundown() error
	// IsKRundownStarted indicates if kernel logger rundown session is started.
	IsKRundownStarted() bool
	// GetTraceHandle returns the handle of the kernel trace session.
	GetTraceHandle() etw.TraceHandle
}

// ktraceController implements KtraceController.
type ktraceController struct {
	// kstreamConfig stores kernel stream specific settings
	kstreamConfig config.KstreamConfig
	// handle is the pointer to kernel trace handle
	handle        etw.TraceHandle
	rundownHandle etw.TraceHandle
	// props is the pointer to event trace properties descriptor
	props           *etw.EventTraceProperties
	rundownProps    *etw.EventTraceProperties
	krundownStarted bool
}

// NewKtraceController spins up a new instance of kernel trace controller.
func NewKtraceController(kstreamConfig config.KstreamConfig) KtraceController {
	return &ktraceController{kstreamConfig: kstreamConfig}
}

// StartKtrace starts a new kernel tracing session. User has the ability to disable
// a specific subset of collected kernel events, even though by default most events
// are forwarded from the provider.
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

	props := &etw.EventTraceProperties{
		Wnode: etw.WnodeHeader{
			BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
			Flags:      etw.WnodeTraceFlagGUID,
			GUID:       etw.KernelTraceControlGUID,
		},
		LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
		LogFileNameOffset: 0,
		EnableFlags:       flags,
		BufferSize:        bufferSize,
		LogFileMode:       etw.ProcessTraceModeRealtime,
		MinimumBuffers:    minBuffers,
		MaximumBuffers:    maxBuffers,
		FlushTimer:        uint32(flushTimer.Seconds()),
	}
	log.Debugf("starting kernel trace with %q event flags", flags)
	handle, err := startTrace(
		ktraceSession,
		props,
	)

	if err == nil {
		if !handle.IsValid() {
			return kerrors.ErrInvalidTrace
		}
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
			// enable rundown kernel logger to at least enumerate open file objects
			if err := k.StartKtraceRundown(); err != nil {
				log.Warn(err)
			}
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

		k.handle = handleCopy
		k.props = props

		if err := enableTrace(etw.KernelAuditAPICallsGUID, handle, 0x10); err != nil {
			return fmt.Errorf("couldn't activate kernel audit API calls logger: %v", err)
		}

		return nil
	}

	switch err {
	case kerrors.ErrTraceAlreadyRunning:
		if err := controlTrace(etw.TraceHandle(0), ktraceSession, props, etw.Query); err == kerrors.ErrKsessionNotRunning {
			return kerrors.ErrCannotUpdateTrace
		}
		if err := controlTrace(etw.TraceHandle(0), ktraceSession, props, etw.Stop); err != nil {
			return kerrors.ErrStopTrace
		}

		time.Sleep(time.Millisecond * 100)
		props := &etw.EventTraceProperties{
			Wnode: etw.WnodeHeader{
				BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
				Flags:      etw.WnodeTraceFlagGUID,
				GUID:       etw.KernelTraceControlGUID,
			},
			LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
			LogFileNameOffset: 0,
			EnableFlags:       flags,
			BufferSize:        bufferSize,
			LogFileMode:       etw.ProcessTraceModeRealtime,
			MinimumBuffers:    minBuffers,
			MaximumBuffers:    maxBuffers,
			FlushTimer:        uint32(flushTimer.Seconds()),
		}
		handle, err := startTrace(
			ktraceSession,
			props,
		)
		if err != nil {
			return kerrors.ErrRestartTrace
		}
		if !handle.IsValid() {
			return kerrors.ErrInvalidTrace
		}
		handleCopy := handle

		sysTraceFlags := make([]etw.EventTraceFlags, 8)
		if err := etw.SetTraceInformation(handle, etw.TraceSystemTraceEnableFlagsInfo, sysTraceFlags); err != nil {
			if err := k.StartKtraceRundown(); err != nil {
				log.Warn(err)
			}
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

		k.handle = handleCopy
		k.props = props
		return nil

	case kerrors.ErrTraceNoSysResources:
		// get the number of maximum allowed loggers from registry
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, etwMaxLoggersPath, registry.QUERY_VALUE)
		if err != nil {
			return err
		}
		defer key.Close()
		v, _, err := key.GetIntegerValue(etwMaxLoggersValue)
		if err != nil {
			return err
		}
		return fmt.Errorf(`the limit for logging sessions on your system is %d. Please consider increasing this number `+
			`by editing HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers key in registry. `+
			`Permissible values are 32 through 256 inclusive, and a reboot is required for any change to take effect`, v)

	default:
		return err
	}
}

// StartKtraceRundown initiates the kernel logger rundown session that will enumerate open file objects
// we can use to match file names in file system kernel events.
func (k *ktraceController) StartKtraceRundown() error {
	props := &etw.EventTraceProperties{
		Wnode: etw.WnodeHeader{
			BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
			Flags:      etw.WnodeTraceFlagGUID,
		},
		LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
		LogFileNameOffset: 0,
		BufferSize:        maxBufferSize,
		LogFileMode:       etw.ProcessTraceModeRealtime,
	}
	k.rundownProps = props
	handle, err := startTrace(
		krundownSession,
		props,
	)
	if err == kerrors.ErrTraceAlreadyRunning {
		if err := controlTrace(handle, krundownSession, props, etw.Stop); err != nil {
			return kerrors.ErrStopTrace
		}
		props := &etw.EventTraceProperties{
			Wnode: etw.WnodeHeader{
				BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
				Flags:      etw.WnodeTraceFlagGUID,
			},
			LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
			LogFileNameOffset: 0,
			BufferSize:        maxBufferSize,
			LogFileMode:       etw.ProcessTraceModeRealtime,
		}
		handle, err = startTrace(
			krundownSession,
			props,
		)
		if err != nil {
			return kerrors.ErrRestartTrace
		}
	}
	if err := enableTrace(etw.KernelRundownGUID, handle, 0x10); err != nil {
		return fmt.Errorf("couldn't activate kernel rundown logger: %v", err)
	}
	k.rundownHandle = handle
	k.krundownStarted = true

	return nil
}

//func startKtrace() error {
//	props := &etw.EventTraceProperties{
//		Wnode: etw.WnodeHeader{
//			BufferSize: uint32(unsafe.Sizeof(etw.EventTraceProperties{})) + 2*maxStringLen,
//			Flags:      etw.WnodeTraceFlagGUID,
//		},
//		LoggerNameOffset:  uint32(unsafe.Sizeof(etw.EventTraceProperties{})),
//		LogFileNameOffset: 0,
//		BufferSize:        maxBufferSize,
//		LogFileMode:       etw.ProcessTraceModeRealtime,
//	}
//	handle, err := startTrace(
//		ktraceSession,
//		props,
//	)
//	if err := enableTrace(etw.KernelRundownGUID, handle, 0x10); err != nil {
//		return fmt.Errorf("couldn't activate kernel rundown logger: %v", err)
//	}
//
//
//	return nil
//}

// IsKRundownStarted indicates if kernel logger rundown session is started.
func (k *ktraceController) IsKRundownStarted() bool {
	return k.krundownStarted
}

// CloseKtrace stops currently running kernel trace session.
func (k *ktraceController) CloseKtrace() error {
	// flush pending event buffers
	if err := controlTrace(k.handle, ktraceSession, k.props, etw.Flush); err != nil {
		log.Warnf("couldn't flush kernel trace session: %v", err)
	}
	time.Sleep(time.Millisecond * 100)
	if err := controlTrace(k.handle, ktraceSession, k.props, etw.Stop); err != nil {
		return fmt.Errorf("couldn't stop kernel trace session: %v", err)
	}
	if k.rundownHandle.IsValid() {
		if err := controlTrace(k.rundownHandle, krundownSession, k.rundownProps, etw.Stop); err != nil {
			log.Warn(err)
		}
	}
	k.krundownStarted = false
	return nil
}

// GetTraceHandle returns the handle of the kernel trace session.
func (k *ktraceController) GetTraceHandle() etw.TraceHandle {
	return k.handle
}
