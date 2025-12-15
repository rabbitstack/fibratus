/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package client

import (
	"time"

	"github.com/cenkalti/backoff/v4"
)

type expBackOff struct {
	b *backoff.ExponentialBackOff
}

func newExpBackOff(maxElapsedTime time.Duration) *expBackOff {
	b := &expBackOff{
		b: &backoff.ExponentialBackOff{
			InitialInterval:     time.Second,
			RandomizationFactor: backoff.DefaultRandomizationFactor,
			Multiplier:          backoff.DefaultMultiplier,
			MaxInterval:         time.Second * 10,
			MaxElapsedTime:      maxElapsedTime,
			Stop:                backoff.Stop,
			Clock:               backoff.SystemClock,
		},
	}

	b.b.Reset()

	return b
}

func (b *expBackOff) retry(o func() error) error {
	return backoff.Retry(o, b.b)
}

func (b *expBackOff) nextBackOff() time.Duration {
	return b.b.NextBackOff()
}
