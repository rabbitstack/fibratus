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
	libntfs "github.com/rabbitstack/fibratus/pkg/fs/ntfs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"os"
)

// ProcessorType is an alias for the event processor type
type ProcessorType uint8

const (
	// Ps represents the process event processor.
	Ps ProcessorType = iota
	// Fs represents the file system event processor.
	Fs
	// Registry represents the registry event processor.
	Registry
	// Image represents the image event processor.
	Image
	// Net represents the network event processor.
	Net
	// Handle represents the handle event processor.
	Handle
	// Mem represents the memory event processor.
	Mem
)

// Processor is the minimal interface that each event stream processor has to satisfy. The event processor
// has the ability to augment events with additional parameters. It is also capable of building a state machine
// from the flow of events going through it.
type Processor interface {
	// ProcessEvent receives an existing event possibly mutating its state.
	// If it returns true, the next processor in the chain is evaluated.
	ProcessEvent(*kevent.Kevent) (*kevent.Kevent, bool, error)

	// Name returns a human-readable name of this processor.
	Name() ProcessorType

	// Close closes the processor and disposes allocated resources.
	Close()
}

// String returns a human-friendly processor name.
func (typ ProcessorType) String() string {
	switch typ {
	case Ps:
		return "process"
	case Fs:
		return "file"
	case Registry:
		return "registry"
	case Image:
		return "image"
	case Net:
		return "net"
	case Handle:
		return "handle"
	case Mem:
		return "mem"
	default:
		return "unknown"
	}
}

// parseImageFileCharacteristics parses the PE structure for the file path
// residing in the given event parameters. The preferred method for getting
// the file data is accessing the raw device and consuming the blob data.
// If this operation fails, we fallback to using the regular file access.
// The given event is decorated with various parameters extracted from PE
// data. Most notably, parameters that indicate whether the file is a DLL,
// executable image, or a Windows driver.
func parseImageFileCharacteristics(e *kevent.Kevent) error {
	filename := e.GetParamAsString(kparams.FileName)
	data := make([]byte, os.Getpagesize())
	f, err := os.Open(filename)
	if err != nil {
		// read file data blob from raw device
		// if the regular file access fails
		ntfs := libntfs.NewFS()
		data, _, err = ntfs.Read(filename, 0, int64(os.Getpagesize()))
		defer ntfs.Close()
		if err != nil {
			return err
		}
		goto parsePe
	}
	defer f.Close()
	if _, err = f.Read(data); err != nil {
		return err
	}
parsePe:
	// parse image file
	pefile, err := pe.ParseBytes(data, pe.WithSections(), pe.WithSymbols())
	if err != nil {
		return err
	}
	// append parameters
	e.AppendParam(kparams.FileIsDLL, kparams.Bool, pefile.IsDLL)
	e.AppendParam(kparams.FileIsDriver, kparams.Bool, pefile.IsDriver)
	e.AppendParam(kparams.FileIsExecutable, kparams.Bool, pefile.IsExecutable)

	return nil
}
