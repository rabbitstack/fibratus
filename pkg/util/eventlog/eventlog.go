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
	"golang.org/x/sys/windows/registry"
)

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

// LevelFromString resolves the eventlog levle from string
func LevelFromString(s string) Level {
	switch s {
	case "info", "INFO":
		return Info
	case "warn", "warning", "WARN", "WARNING":
		return Warn
	case "erro", "error", "ERRO", "ERROR":
		return Erro
	default:
		panic(fmt.Sprintf("unrecognized evtlog level: %s", s))
	}
}

// ErrKeyExists signals that the registry key already exists
type ErrKeyExists struct {
	src string
	key string
}

func (e ErrKeyExists) Error() string {
	return fmt.Sprintf("%s\\%s already exists", e.key, e.src)
}

// Install modifies PC registry to allow logging with an event source src.
// It adds all required keys and values to the event log registry key.
// Install uses msgFile as the event message file. If useExpandKey is true,
// the event message file is installed as REG_EXPAND_SZ value,
// otherwise as REG_SZ. Use bitwise of log.Error, log.Warning and
// log.Info to specify events supported by the new event source.
func Install(src, f, key string, useExpandKey bool, eventsSupported, cats uint32) error {
	appkey, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer appkey.Close()

	sk, alreadyExist, err := registry.CreateKey(appkey, src, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer sk.Close()
	if alreadyExist {
		return ErrKeyExists{src, key}
	}

	err = sk.SetDWordValue("CustomSource", 1)
	if err != nil {
		return err
	}
	if useExpandKey {
		err = sk.SetExpandStringValue("EventMessageFile", f)
	} else {
		err = sk.SetStringValue("EventMessageFile", f)
	}
	if err != nil {
		return err
	}
	if useExpandKey {
		err = sk.SetExpandStringValue("CategoryMessageFile", f)
	} else {
		err = sk.SetStringValue("CategoryMessageFile", f)
	}
	if err != nil {
		return err
	}
	err = sk.SetDWordValue("TypesSupported", eventsSupported)
	if err != nil {
		return err
	}
	err = sk.SetDWordValue("CategoryCount", cats)
	if err != nil {
		return err
	}
	return nil
}
