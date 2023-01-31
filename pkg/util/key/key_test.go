//go:build windows
// +build windows

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

package key

import (
	"github.com/rabbitstack/fibratus/pkg/zsyscall/registry"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	lookupSids = func() ([]string, error) {
		return []string{"S-1-5-21-2271034452-2606270099-984871569-500", "S-1-5-21-2271034452-2606270099-984871569-501"}, nil
	}
}

func TestFormatKey(t *testing.T) {
	root, key := Format(`\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`)
	assert.Equal(t, registry.LocalMachine, root)
	assert.Equal(t, `SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`, key)

	root, key = Format(`\Registry\Machine\SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`)
	assert.Equal(t, registry.LocalMachine, root)
	assert.Equal(t, `SYSTEM\ControlSet001\Services\Windows Workflow Foundation 4.0.0.0\Linkage`, key)

	root, key = Format(`\REGISTRY\MACHINE`)
	assert.Equal(t, registry.LocalMachine, root)
	assert.Empty(t, key)

	root, key = Format(`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\Console`)
	assert.Equal(t, registry.CurrentUser, root)
	assert.Equal(t, `Console`, key)

	root, key = Format(`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes`)
	assert.Equal(t, registry.CurrentUser, root)
	assert.Equal(t, `Software\Classes`, key)

	root, key = Format(`\REGISTRY\USER\S-1-5-21-2271034452-2606270099-984871569-500\_Classes\.all`)
	assert.Equal(t, registry.CurrentUser, root)
	assert.Equal(t, `Software\Classes\.all`, key)
}
