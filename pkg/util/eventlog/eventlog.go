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

package eventlog

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/event"
	"golang.org/x/sys/windows/registry"
)

const (
	// Source represents the event source that generates the alerts
	Source = "Fibratus"
	// Levels designates the supported eventlog levels
	Levels = uint32(Info | Warn | Erro)
	// msgFile specifies the location of the eventlog message DLL
	msgFile = "%ProgramFiles%\\Fibratus\\fibratus.dll"
	// keyName represents the registry key under which the eventlog source is registered
	keyName = `SYSTEM\CurrentControlSet\Services\EventLog\Application`
)

// ErrKeyExists signals that the registry key already exists
var ErrKeyExists = fmt.Errorf("%s\\%s already exists", keyName, Source)

// categoryCount indicates the number of current event categories
var categoryCount = uint32(len(event.Categories()))

// Level is the type definition for the eventlog log level
type Level uint16

const (
	// Info represents the info log level
	Info Level = 4
	// Warn represents the warning info level
	Warn Level = 2
	// Erro represents the error log level
	Erro Level = 1
)

// Install modifies PC registry to allow logging with an event source src.
// It adds all required keys and values to the event log registry key.
// Install uses msgFile as the event message file. If useExpandKey is true,
// the event message file is installed as REG_EXPAND_SZ value,
// otherwise as REG_SZ. Use bitwise of Errr, Warn, and Info to specify events
// supported by the new event source.
func Install(eventsSupported uint32) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyName, registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer key.Close()

	sk, exists, err := registry.CreateKey(key, Source, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer sk.Close()
	if exists {
		return ErrKeyExists
	}

	err = sk.SetDWordValue("CustomSource", 1)
	if err != nil {
		return err
	}
	err = sk.SetExpandStringValue("EventMessageFile", msgFile)
	if err != nil {
		return err
	}
	err = sk.SetExpandStringValue("CategoryMessageFile", msgFile)
	if err != nil {
		return err
	}
	err = sk.SetDWordValue("TypesSupported", eventsSupported)
	if err != nil {
		return err
	}
	err = sk.SetDWordValue("CategoryCount", categoryCount)
	if err != nil {
		return err
	}
	return nil
}
