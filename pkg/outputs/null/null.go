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

package null

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
)

var blackholeEventsCount = expvar.NewInt("output.null.blackhole.events")

// null output devours kernel events the same way a black hole swallows the light
type null struct{}

func init() {
	outputs.Register(outputs.Null, initNull)
}

func initNull(config outputs.Config) (outputs.OutputGroup, error) {
	return outputs.Success(&null{}), nil
}

func (null) Close() error   { return nil }
func (null) Connect() error { return nil }
func (null) Publish(batch *kevent.Batch) error {
	blackholeEventsCount.Add(batch.Len())
	return nil
}
