/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package symbolize

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
)

func TestSymbolFromRVA(t *testing.T) {
	var tests = []struct {
		rva            va.Address
		exports        map[uint32]string
		expectedSymbol string
	}{
		{va.Address(317949), map[uint32]string{
			9824:   "SHCreateScopeItemFromShellItem",
			23248:  "SHCreateScopeItemFromIDList",
			165392: "DllGetClassObject",
			186368: "SHCreateSearchIDListFromAutoList",
			238048: "DllCanUnloadNow",
			240112: "IsShellItemInSearchIndex",
			240304: "IsMSSearchEnabled",
			272336: "SHSaveBinaryAutoListToStream",
			310672: "DllMain",
			317920: "",
			320864: "",
			434000: "SHCreateAutoList",
			434016: "SHCreateAutoListWithID",
			555040: "CreateDefaultProviderResolver",
			571136: "GetGatherAdmin",
			572592: "SEARCH_RemoteLocationsCscStateCache_IsRemoteLocationInCsc"},
			"?",
		},
		{va.Address(434011), map[uint32]string{
			9824:   "SHCreateScopeItemFromShellItem",
			23248:  "SHCreateScopeItemFromIDList",
			165392: "DllGetClassObject",
			186368: "SHCreateSearchIDListFromAutoList",
			238048: "DllCanUnloadNow",
			240112: "IsShellItemInSearchIndex",
			240304: "IsMSSearchEnabled",
			272336: "SHSaveBinaryAutoListToStream",
			310672: "DllMain",
			317920: "",
			320864: "",
			434000: "SHCreateAutoList",
			434016: "SHCreateAutoListWithID",
			555040: "CreateDefaultProviderResolver",
			571136: "GetGatherAdmin",
			572592: "SEARCH_RemoteLocationsCscStateCache_IsRemoteLocationInCsc"},
			"SHCreateAutoList",
		},
		{va.Address(4532), map[uint32]string{
			9824:   "SHCreateScopeItemFromShellItem",
			23248:  "SHCreateScopeItemFromIDList",
			165392: "DllGetClassObject",
			186368: "SHCreateSearchIDListFromAutoList",
			238048: "DllCanUnloadNow",
			240112: "IsShellItemInSearchIndex",
			240304: "IsMSSearchEnabled",
			572592: "SEARCH_RemoteLocationsCscStateCache_IsRemoteLocationInCsc"},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedSymbol, func(t *testing.T) {
			exps := &ModuleExports{exps: tt.exports}
			assert.Equal(t, tt.expectedSymbol, exps.SymbolFromRVA(tt.rva))
		})
	}
}
