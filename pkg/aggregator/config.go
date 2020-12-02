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

package aggregator

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"time"
)

const (
	flushPeriod  = "aggregator.flush-period"
	flushTimeout = "aggregator.flush-timeout"
)

// Config contains aggregator-specific configuration tweaks.
type Config struct {
	// FlushPeriod determines the period for flushing batches to outputs.
	FlushPeriod time.Duration `json:"aggregator.flush-period" yaml:"aggregator.flush-period"`
	// FlushTimeout represents the max time to wait before announcing failed flushing of enqueued events
	FlushTimeout time.Duration `json:"aggregator.flush-timeout" yaml:"aggregator.flush-timeout"`
}

// AddFlags registers persistent aggregator flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Duration(flushPeriod, time.Millisecond*200, "Determines the period for flushing batches to outputs")
	flags.Duration(flushTimeout, time.Second*4, "Represents the max time to wait before announcing failed flushing of enqueued events on aggregator shutdown")
}

// InitFromViper initializes aggregator flags from viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.FlushPeriod = v.GetDuration(flushPeriod)
	c.FlushTimeout = v.GetDuration(flushTimeout)
}
