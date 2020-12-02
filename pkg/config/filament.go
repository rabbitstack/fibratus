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

package config

import (
	"github.com/spf13/viper"
	"time"
)

const (
	filamentName = "filament.name"
	filamentPath = "filament.path"
)

// FilamentConfig stores config parameters for tweaking the behaviour of the filament engine.
type FilamentConfig struct {
	Name        string
	Path        string
	FlushPeriod time.Duration
}

func (f *FilamentConfig) initFromViper(v *viper.Viper) {
	f.Name = v.GetString(filamentName)
	f.Path = v.GetString(filamentPath)
}
