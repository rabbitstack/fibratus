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

package spinner

import (
	"github.com/briandowns/spinner"
	"time"
)

// Show creates a new spinner and starts it.
func Show(prefix string) *spinner.Spinner {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond) // Build our spinner
	s.Prefix = "> " + prefix + " "
	s.HideCursor = true
	s.Start()
	return s
}
