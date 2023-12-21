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

package fields

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLookup(t *testing.T) {
	assert.Equal(t, PsPid, Lookup("ps.pid"))
	assert.Equal(t, Field("ps.envs[ALLUSERSPROFILE]"), Lookup("ps.envs[ALLUSERSPROFILE]"))
	assert.Empty(t, Lookup("ps.envs[ALLUSERSPROFILE].env"))
	assert.Empty(t, Lookup("ps.envs[ALLUSERSPROFILE"))
	assert.Empty(t, Lookup("ps.envs["))
	assert.Empty(t, Lookup("ps.envs[]"))
	assert.Equal(t, PsEnvs, Lookup("ps.envs"))
	assert.Equal(t, Field("ps.pe.sections[.debug$S].entropy"), Lookup("ps.pe.sections[.debug$S].entropy"))
	assert.Empty(t, Lookup("ps.pe.sections[.debug$S"))
	assert.Empty(t, Lookup("ps.pe.sections[.debug$S]"))
	assert.Empty(t, Lookup("ps.pe.sections[.debug$S]."))
	assert.Empty(t, Lookup("ps.pe.sections[.debug$S].e"))
	assert.Equal(t, Field("ps.ancestor[1].name"), Lookup("ps.ancestor[1].name"))
	assert.Equal(t, Field("ps.ancestor[root].name"), Lookup("ps.ancestor[root].name"))
	assert.Equal(t, Field("ps.ancestor[any].pid"), Lookup("ps.ancestor[any].pid"))
	assert.Equal(t, Field("ps.ancestor[2].sid"), Lookup("ps.ancestor[2].sid"))
	assert.Empty(t, Lookup("ps.ancestor[ro].name"))
	assert.Equal(t, Field("kevt.arg[exe]"), Lookup("kevt.arg[exe]"))
	assert.Empty(t, Lookup("kevt.arg"))
}

func TestIsDeprecated(t *testing.T) {
	deprecated, d := IsDeprecated(PsSiblingPid)
	assert.True(t, deprecated)
	assert.NotNil(t, d)
}
