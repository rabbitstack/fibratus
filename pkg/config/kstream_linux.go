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

import "github.com/spf13/viper"

type KstreamConfig struct {
	RingBufferSize        int `json:"ring-buffer-size" yaml:"ring-buffer-size"`
	Watermark             int `json:"watermark" yaml:"watermark"`
	VerifierLogsize       int
	EnableVerifierLogging bool
	// BlacklistKevents are kernel event names that will be dropped from the kernel event stream.
	BlacklistKevents []string `json:"blacklist.events" yaml:"blacklist.events"`
	// BlacklistImages are process image names that will be rejected if they generate a kernel event.
	BlacklistImages []string `json:"blacklist.images" yaml:"blacklist.images"`
}

func (k *KstreamConfig) initFromViper(v *viper.Viper) {

}
