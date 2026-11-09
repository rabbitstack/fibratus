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
package rules

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	keyPath  = Key{Field: fields.RegistryPath}
	filePath = Key{Field: fields.FilePath}
	fileName = Key{Field: fields.FileName}
	fileExt  = Key{Field: fields.FileExtension}
	fileOp   = Key{Field: fields.FileOperation}
	exeArg   = Key{Field: fields.EvtArg, Arg: params.Exe}
)

// values makes the value function out of the attribute values.
func values(attrs map[Key]string) ValueFunc {
	return func(k Key) (string, bool) {
		v, ok := attrs[k]
		return v, ok
	}
}

func approversOf(t *testing.T, conditions ...string) *Approvers {
	t.Helper()
	var rules []*policy.RuleDef
	for i, c := range conditions {
		rules = append(rules, def(string(rune('a'+i)), c))
	}
	return mustRuleSet(t, true, behaviour("p", rules...)).Approvers()
}

func TestApproversRegistry(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('HKEY_LOCAL_MACHINE*SAM*', 'HKEY_USERS*Run')",
		"evt.name = 'RegOpenKey' and registry.path icontains 'Credentials'",
	)
	require.True(t, a.Narrows(event.RegOpenKey))
	assert.Len(t, a.For(event.RegOpenKey), 2)

	var tests = []struct {
		path     string
		approved bool
	}{
		{`HKEY_LOCAL_MACHINE\SECURITY\SAM\Domains`, true},
		{`hkey_users\s-1-5\software\run`, true},
		{`HKEY_CURRENT_USER\Software\CREDENTIALS\x`, true},
		{`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft`, false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.approved, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: tt.path})))
		})
	}

	// other event types are not narrowed by the registry approvers
	assert.True(t, a.Approve(event.CreateProcess, values(nil)))
	assert.False(t, a.Narrows(event.CreateFile))
}

func TestApproversRuleWithoutPredicateApprovesAll(t *testing.T) {
	// one rule consumes all key opens, so the predicates
	// of the other rule can't narrow the events down
	a := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('HKEY_LOCAL_MACHINE*SAM*')",
		"evt.name = 'RegOpenKey' and ps.name = 'cmd.exe'",
	)
	assert.False(t, a.Narrows(event.RegOpenKey))
	assert.Empty(t, a.For(event.RegOpenKey))
	assert.True(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: `HKEY_CURRENT_USER\x`})))
	assert.Equal(t, []event.Type{event.RegOpenKey}, a.Types())

	// the order of the rules doesn't matter
	a = approversOf(t,
		"evt.name = 'RegOpenKey' and ps.name = 'cmd.exe'",
		"evt.name = 'RegOpenKey' and registry.path imatches ('HKEY_LOCAL_MACHINE*SAM*')",
	)
	assert.False(t, a.Narrows(event.RegOpenKey))
}

func TestApproversOnlyNecessaryConditionsAreUsed(t *testing.T) {
	var tests = []struct {
		name string
		cond string
	}{
		{"or branch", "evt.name = 'RegOpenKey' and (registry.path imatches ('a*') or ps.name = 'x')"},
		{"negation", "evt.name = 'RegOpenKey' and not registry.path imatches ('a*')"},
		{"unsupported operator", "evt.name = 'RegOpenKey' and registry.path contains 'a'"},
		{"unsupported operator for starts with", "evt.name = 'RegOpenKey' and registry.path startswith 'a'"},
		{"non literal operand", "evt.name = 'RegOpenKey' and registry.path = ps.name"},
		{"event name or other event", "evt.name = 'RegOpenKey' or evt.name = 'RegSetValue'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := approversOf(t, tt.cond)
			assert.False(t, a.Narrows(event.RegOpenKey), "the rule needs all key opens")
			assert.True(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: "zzz"})))
		})
	}
}

func TestApproversNestedConjunctionsAndParens(t *testing.T) {
	a := approversOf(t, "evt.name = 'RegOpenKey' and (ps.name = 'a.exe' and (registry.path iin ('HKLM\\Foo')))")
	require.True(t, a.Narrows(event.RegOpenKey))
	assert.True(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: `hklm\FOO`})))
	assert.False(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: `hklm\bar`})))
}

func TestApproversAreUnique(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('abc*')",
		"evt.name = 'RegOpenKey' and registry.path imatches ('abc*')",
	)
	assert.Len(t, a.For(event.RegOpenKey), 1)
}

func TestApproverIsConjunctionOfPredicates(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.name iin ('ntds.dit') and file.extension = '.dit'",
	)
	require.True(t, a.Narrows(event.CreateFile))

	open := func(name, ext string) ValueFunc {
		return values(map[Key]string{fileOp: "OPEN", fileName: name, fileExt: ext})
	}
	assert.True(t, a.Approve(event.CreateFile, open("NTDS.dit", ".dit")))
	// every predicate of the rule must hold
	assert.False(t, a.Approve(event.CreateFile, open("NTDS.dit", ".txt")))
	assert.False(t, a.Approve(event.CreateFile, open("other.dit", ".dit")))
	// the rule requires the open operation
	assert.False(t, a.Approve(event.CreateFile, values(map[Key]string{fileOp: "CREATE", fileName: "ntds.dit", fileExt: ".dit"})))
}

func TestApproversUnresolvedValuesDontReject(t *testing.T) {
	a := approversOf(t, "evt.name = 'CreateFile' and file.path imatches ('?:\\Windows\\*') and file.name = 'a.dll'")
	require.True(t, a.Narrows(event.CreateFile))
	// only the file name is resolved by the event source
	assert.True(t, a.Approve(event.CreateFile, values(map[Key]string{fileName: "a.dll"})))
	assert.False(t, a.Approve(event.CreateFile, values(map[Key]string{fileName: "b.dll"})))
	// nothing is resolved
	assert.True(t, a.Approve(event.CreateFile, values(nil)))
}

func TestApproversFiles(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.path imatches ('?:\\Windows\\System32\\config\\SAM')",
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.extension in ('.dll', '.exe')",
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.name iin ('ntds.dit')",
	)
	require.True(t, a.Narrows(event.CreateFile))

	open := func(attrs map[Key]string) bool {
		attrs[fileOp] = "OPEN"
		return a.Approve(event.CreateFile, values(attrs))
	}
	assert.True(t, open(map[Key]string{filePath: `C:\Windows\System32\config\sam`}))
	assert.True(t, open(map[Key]string{fileExt: ".dll"}))
	assert.True(t, open(map[Key]string{fileName: "NTDS.DIT"}))
	assert.False(t, open(map[Key]string{filePath: `C:\Temp\a.txt`, fileExt: ".txt", fileName: "a.txt"}))
}

func TestApproversFileRuleWithoutPredicate(t *testing.T) {
	for _, cond := range []string{
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and ps.name = 'cmd.exe'",
		"evt.name = 'CreateFile' and ps.name = 'cmd.exe'",
	} {
		a := approversOf(t,
			"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.name = 'a.dll'",
			cond,
		)
		assert.False(t, a.Narrows(event.CreateFile), cond)
	}
}

func TestApproversFileRulesThatCantBeOpens(t *testing.T) {
	// the rule that requires the file creation consumes
	// no file opens, so it can't approve them
	a := approversOf(t, "evt.name = 'CreateFile' and file.operation = 'CREATE' and file.path imatches ('c:\\temp\\*')")
	opened := values(map[Key]string{fileOp: "OPEN", filePath: `c:\temp\a.exe`})
	assert.False(t, a.Approve(event.CreateFile, opened))
	assert.True(t, a.Approve(event.CreateFile, values(map[Key]string{fileOp: "CREATE", filePath: `c:\temp\a.exe`})))
}

func TestApproversFileObjectDependents(t *testing.T) {
	// the file deletion needs the file opens to learn the file path
	for _, evt := range []string{"SetFileInformation", "DeleteFile", "RenameFile"} {
		t.Run(evt, func(t *testing.T) {
			a := approversOf(t,
				"evt.name = 'CreateFile' and file.operation = 'OPEN' and file.name = 'a.dll'",
				"evt.name = '"+evt+"' and ps.name = 'cmd.exe'",
			)
			assert.False(t, a.Narrows(event.CreateFile))
			assert.True(t, a.Approve(event.CreateFile, values(map[Key]string{fileOp: "OPEN", fileName: "b.dll"})))
		})
	}

	// the dependency alone registers the approve all entry
	a := approversOf(t, "evt.name = 'DeleteFile'")
	assert.Equal(t, []event.Type{event.CreateFile}, a.Types())
	assert.False(t, a.Narrows(event.CreateFile))
}

func TestApproversProcessAccess(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'OpenProcess' and evt.arg[exe] imatches ('?:\\Windows\\System32\\lsass.exe')",
		"evt.name = 'OpenThread' and evt.arg[exe] iin ('c:\\windows\\system32\\csrss.exe')",
	)
	exe := func(p string) ValueFunc { return values(map[Key]string{exeArg: p}) }

	// the approvers are registered per event type
	require.True(t, a.Narrows(event.OpenProcess))
	require.True(t, a.Narrows(event.OpenThread))
	assert.True(t, a.Approve(event.OpenProcess, exe(`C:\Windows\System32\LSASS.exe`)))
	assert.False(t, a.Approve(event.OpenProcess, exe(`C:\Windows\System32\csrss.exe`)))
	assert.True(t, a.Approve(event.OpenThread, exe(`C:\Windows\System32\csrss.exe`)))
	assert.False(t, a.Approve(event.OpenThread, exe(`C:\Windows\System32\lsass.exe`)))

	a = approversOf(t,
		"evt.name = 'OpenProcess' and evt.arg[exe] imatches ('?:\\Windows\\System32\\lsass.exe')",
		"evt.name = 'OpenProcess' and ps.name = 'a.exe'",
	)
	assert.False(t, a.Narrows(event.OpenProcess))
}

func TestApproversEventTypesAreIndependent(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('a*')",
		"evt.name = 'CreateFile' and file.operation = 'OPEN' and ps.name = 'cmd.exe'",
		"evt.name = 'OpenProcess' and evt.arg[exe] imatches ('b*')",
	)
	assert.True(t, a.Narrows(event.RegOpenKey))
	assert.False(t, a.Narrows(event.CreateFile))
	assert.True(t, a.Narrows(event.OpenProcess))
	assert.Equal(t, []event.Type{event.CreateFile, event.OpenProcess, event.RegOpenKey}, a.Types())
}

func TestApproversForEventsNoRuleNarrows(t *testing.T) {
	// the rules for events that approvers can't narrow register nothing
	a := approversOf(t, "evt.name = 'CreateProcess' and ps.name = 'cmd.exe'")
	assert.Empty(t, a.Types())
	assert.True(t, a.Approve(event.RegOpenKey, values(nil)))

	// no rules at all
	rs, err := NewRuleSet(nil)
	require.NoError(t, err)
	assert.Empty(t, rs.Approvers().Types())
	assert.True(t, rs.Approvers().Approve(event.RegOpenKey, values(nil)))

	// nil approvers don't reject anything
	var nilApprovers *Approvers
	assert.True(t, nilApprovers.Approve(event.RegOpenKey, values(nil)))
	assert.False(t, nilApprovers.Narrows(event.RegOpenKey))
	assert.Empty(t, nilApprovers.Types())
	assert.Empty(t, nilApprovers.String())
}

func TestApproversSequenceStepsAreIndependent(t *testing.T) {
	a := approversOf(t, `sequence
		maxspan 1m
		|evt.name = 'RegOpenKey' and registry.path imatches ('a*')| by ps.uuid
		|evt.name = 'CreateProcess'| by ps.uuid
	`)
	require.True(t, a.Narrows(event.RegOpenKey))
	assert.True(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: "abc"})))
	assert.False(t, a.Approve(event.RegOpenKey, values(map[Key]string{keyPath: "xyz"})))

	// the sequence step without predicate needs all key opens
	a = approversOf(t, `sequence
		maxspan 1m
		|evt.name = 'CreateProcess'| by ps.uuid
		|evt.name = 'RegOpenKey' and ps.name = 'a.exe'| by ps.uuid
	`)
	assert.False(t, a.Narrows(event.RegOpenKey))
}

func TestApproversFollowTheRuleSet(t *testing.T) {
	// the approvers are recomputed for every rule set, so the new
	// rule set that is built after the rules reload carries new approvers
	before := approversOf(t, "evt.name = 'RegOpenKey' and registry.path imatches ('a*')")
	after := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('a*')",
		"evt.name = 'RegOpenKey' and registry.path imatches ('b*')",
	)
	b := values(map[Key]string{keyPath: "bcd"})
	assert.False(t, before.Approve(event.RegOpenKey, b))
	assert.True(t, after.Approve(event.RegOpenKey, b))
}

func TestApproverCaps(t *testing.T) {
	// the event source that can only resolve registry paths
	caps := ApproverCaps{Keys: map[event.Type][]Key{event.RegOpenKey: {keyPath}}}
	rs, err := NewRuleSet([]*policy.Policy{behaviour("p",
		def("reg", "evt.name = 'RegOpenKey' and registry.path imatches ('a*')"),
		def("file", "evt.name = 'CreateFile' and file.path imatches ('a*')"),
		def("del", "evt.name = 'DeleteFile'"),
	)}, WithApproverCaps(caps))
	require.NoError(t, err)

	assert.Equal(t, []event.Type{event.RegOpenKey}, rs.Approvers().Types())
	assert.False(t, rs.Approvers().Approve(event.RegOpenKey, values(map[Key]string{keyPath: "b"})))

	// the key not declared by the capabilities is not used
	rs, err = NewRuleSet([]*policy.Policy{behaviour("p",
		def("reg", "evt.name = 'RegOpenKey' and registry.path imatches ('a*') and evt.arg[exe] = 'x'"),
	)}, WithApproverCaps(caps))
	require.NoError(t, err)
	require.True(t, rs.Approvers().Narrows(event.RegOpenKey))
	assert.Len(t, rs.Approvers().For(event.RegOpenKey)[0].Matchers, 1)
}

func TestApproversString(t *testing.T) {
	a := approversOf(t,
		"evt.name = 'RegOpenKey' and registry.path imatches ('A*') and ps.name = 'x'",
		"evt.name = 'CreateFile'",
		"evt.name = 'OpenProcess' and evt.arg[exe] iin ('b.exe')",
	)
	s := a.String()
	assert.Contains(t, s, "RegOpenKey: (registry.path imatches ('A*'))")
	assert.Contains(t, s, "CreateFile: all")
	assert.Contains(t, s, "OpenProcess: (evt.arg[exe] iin ('b.exe'))")
}

func TestReportCarriesApprovers(t *testing.T) {
	rs := mustRuleSet(t, true, behaviour("p", def("a", "evt.name = 'RegOpenKey' and registry.path imatches ('a*')")))
	require.NotNil(t, rs.Report().Approvers)
	assert.Same(t, rs.Report().Approvers, rs.Approvers())
	assert.True(t, rs.Approvers().Narrows(event.RegOpenKey))
}

func TestRuleBucket(t *testing.T) {
	r1, err := NewRule(def("a", "evt.name = 'CreateFile' and file.path = 'x'"), nil)
	require.NoError(t, err)
	r2, err := NewRule(def("b", "evt.name = 'CreateFile' and ps.name = 'y' and file.path = 'z'"), nil)
	require.NoError(t, err)
	r1.order, r2.order = 0, 1

	var b RuleBucket
	assert.Equal(t, 0, b.Len())
	b.AddRule(r1)
	b.AddRule(r1)
	b.AddRule(r2)
	assert.Equal(t, 2, b.Len())
	assert.Equal(t, []*Rule{r1, r2}, b.GetRules())

	// fields are unique across rules in the bucket
	flds := make([]string, 0)
	for _, f := range b.Fields() {
		flds = append(flds, f.String())
	}
	assert.ElementsMatch(t, []string{"evt.name", "file.path", "ps.name"}, flds)

	// nil bucket is safe to use
	var nilBucket *RuleBucket
	assert.Equal(t, 0, nilBucket.Len())
	assert.Nil(t, nilBucket.GetRules())
	assert.Nil(t, nilBucket.Fields())
}
