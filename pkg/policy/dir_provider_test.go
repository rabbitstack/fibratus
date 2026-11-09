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
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ruleTmpl = `name: %s
id: %s
version: 1.0.0
condition: evt.name = 'CreateProcess'
min-engine-version: 2.0.0
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func writeRule(t *testing.T, dir, file, name, id string) string {
	t.Helper()
	path := filepath.Join(dir, file)
	writeFile(t, path, sprintf(ruleTmpl, name, id))
	return path
}

const (
	id1 = "11111111-1111-4111-8111-111111111111"
	id2 = "22222222-2222-4222-8222-222222222222"
	id3 = "33333333-3333-4333-8333-333333333333"
)

func TestDirProviderLoad(t *testing.T) {
	dir := t.TempDir()
	r1 := writeRule(t, dir, "a_rule.yml", "first rule", id1)
	r2 := writeRule(t, dir, "b_rule.yaml", "second rule", id2)
	writeFile(t, filepath.Join(dir, "notes.txt"), "not a rule")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir.yml"), 0o755)) // directory with yaml ext
	m1 := filepath.Join(dir, "macros", "macros.yml")
	writeFile(t, m1, "- macro: spawn_process\n  expr: evt.name = 'CreateProcess'\n")

	p := NewDirProvider(
		[]string{filepath.Join(dir, "*")},
		[]string{filepath.Join(dir, "macros", "*")},
	)
	assert.Equal(t, DirProviderType, p.Type())

	policies, err := p.Load()
	require.NoError(t, err)
	require.Len(t, policies, 3)

	// macro policies come first
	assert.Equal(t, PolicyID(m1), policies[0].ID)
	assert.Len(t, policies[0].Macros, 1)
	assert.Empty(t, policies[0].Rules)
	assert.Equal(t, BehaviourPolicyType, policies[0].Type)
	assert.Equal(t, YAMLInternalType, policies[0].InternalType)
	assert.Equal(t, "macros", policies[0].Name)

	assert.Equal(t, PolicyID(r1), policies[1].ID)
	assert.Equal(t, "first rule", policies[1].Name)
	assert.Equal(t, "1.0.0", policies[1].Version)
	require.Len(t, policies[1].Rules, 1)
	assert.Equal(t, RuleID(id1), policies[1].Rules[0].ID)
	assert.Equal(t, r1, policies[1].Source)

	assert.Equal(t, PolicyID(r2), policies[2].ID)
}

func TestDirProviderLoadErrors(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "good.yml", "good rule", id1)
	bad := filepath.Join(dir, "bad.yml")
	writeFile(t, bad, "name: only a name\n")
	badMacro := filepath.Join(dir, "macros", "bad.yml")
	writeFile(t, badMacro, "- macro: broken\n")

	p := NewDirProvider([]string{filepath.Join(dir, "*")}, []string{filepath.Join(dir, "macros", "*")})
	policies, err := p.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), bad)
	assert.Contains(t, err.Error(), badMacro)

	// the valid rule is still returned
	require.Len(t, policies, 1)
	assert.Equal(t, "good rule", policies[0].Name)
}

func TestDirProviderInvalidPattern(t *testing.T) {
	p := NewDirProvider([]string{"[invalid"}, nil)
	_, err := p.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid path pattern")
}

func TestDirProviderNoFiles(t *testing.T) {
	p := NewDirProvider([]string{filepath.Join(t.TempDir(), "*")}, nil)
	policies, err := p.Load()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestDirProviderDeduplicatesFiles(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "rule.yml", "rule", id1)

	// both patterns match the same file
	p := NewDirProvider([]string{filepath.Join(dir, "*.yml"), filepath.Join(dir, "rule.*")}, nil)
	policies, err := p.Load()
	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestDirProviderMacroFileWinsOverRulePattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "macros.yml"), "- macro: m\n  expr: evt.name = 'CreateFile'\n")

	// the macro file also matches the rule pattern but must not be decoded as a rule
	p := NewDirProvider([]string{filepath.Join(dir, "*")}, []string{filepath.Join(dir, "macros.yml")})
	policies, err := p.Load()
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Len(t, policies[0].Macros, 1)
}

func TestWatchDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "macros"), 0o755))

	dirs := watchDirs(
		[]string{filepath.Join(dir, "*"), filepath.Join(dir, "*.yml")},
		[]string{filepath.Join(dir, "macros", "*"), filepath.Join(dir, "missing", "*")},
	)
	assert.Equal(t, []string{dir, filepath.Join(dir, "macros")}, dirs)

	// glob meta characters inside directory part climb up to the first plain directory
	dirs = watchDirs([]string{filepath.Join(dir, "mac*", "*.yml")})
	assert.Equal(t, []string{dir}, dirs)
}

type fakeWatcher struct {
	dirs   []string
	notify func()
	closed atomic.Bool
}

func (w *fakeWatcher) Close() error { w.closed.Store(true); return nil }

func newTestProvider(t *testing.T, dir string) (*DirProvider, *fakeWatcher) {
	t.Helper()
	p := NewDirProvider([]string{filepath.Join(dir, "*")}, nil)
	p.debounce = 20 * time.Millisecond
	fw := &fakeWatcher{}
	p.newWatcher = func(dirs []string, notify func()) (watcher, error) {
		fw.dirs, fw.notify = dirs, notify
		return fw, nil
	}
	return p, fw
}

func TestDirProviderDebouncesNotifications(t *testing.T) {
	dir := t.TempDir()
	p, fw := newTestProvider(t, dir)

	var calls atomic.Int32
	called := make(chan struct{}, 4)
	p.SetOnPoliciesChanged(func() { calls.Add(1); called <- struct{}{} })

	require.NoError(t, p.Start())
	assert.Equal(t, []string{dir}, fw.dirs)

	// a burst of notifications results in a single callback
	for i := 0; i < 5; i++ {
		fw.notify()
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("policies changed callback was not invoked")
	}
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load())

	// a later notification triggers another callback
	fw.notify()
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("policies changed callback was not invoked for the second change")
	}
}

func TestDirProviderClose(t *testing.T) {
	dir := t.TempDir()
	p, fw := newTestProvider(t, dir)

	var calls atomic.Int32
	p.SetOnPoliciesChanged(func() { calls.Add(1) })
	require.NoError(t, p.Start())

	// notification pending when the provider is closed must not fire
	fw.notify()
	require.NoError(t, p.Close())
	assert.True(t, fw.closed.Load())
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, int32(0), calls.Load())

	// notifications after close are ignored and close is idempotent
	fw.notify()
	require.NoError(t, p.Close())
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, int32(0), calls.Load())
}

func TestDirProviderStartIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	p, _ := newTestProvider(t, dir)
	var created int
	orig := p.newWatcher
	p.newWatcher = func(dirs []string, notify func()) (watcher, error) {
		created++
		return orig(dirs, notify)
	}
	require.NoError(t, p.Start())
	require.NoError(t, p.Start())
	assert.Equal(t, 1, created)
}

func TestDirProviderStartWithoutDirectories(t *testing.T) {
	p := NewDirProvider([]string{filepath.Join(t.TempDir(), "missing", "*")}, nil)
	p.newWatcher = func([]string, func()) (watcher, error) {
		t.Fatal("watcher shouldn't be created")
		return nil, nil
	}
	require.NoError(t, p.Start())
}

func TestDirProviderStartWatcherError(t *testing.T) {
	p := NewDirProvider([]string{filepath.Join(t.TempDir(), "*")}, nil)
	p.newWatcher = func([]string, func()) (watcher, error) { return nil, errTest }
	err := p.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to watch policy directories")
}

func TestDirProviderConcurrentNotify(t *testing.T) {
	dir := t.TempDir()
	p, fw := newTestProvider(t, dir)
	var calls atomic.Int32
	p.SetOnPoliciesChanged(func() { calls.Add(1) })
	require.NoError(t, p.Start())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				fw.notify()
			}
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	assert.GreaterOrEqual(t, calls.Load(), int32(1))
	require.NoError(t, p.Close())
}

var errTest = fmt.Errorf("test error")

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
