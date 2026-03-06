package terminator

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestKill(t *testing.T) {
	tests := []struct {
		name    string
		spawnFn func(t *testing.T) *exec.Cmd // nil means no process (dead PID scenario)
		pidFn   func(cmd *exec.Cmd) uint32   // derive the PID to pass to Kill
		wantErr bool
	}{
		{
			name: "kills a live cmd.exe process",
			spawnFn: func(t *testing.T) *exec.Cmd {
				return spawnCmdExe(t)
			},
			pidFn: func(cmd *exec.Cmd) uint32 {
				return uint32(cmd.Process.Pid)
			},
			wantErr: false,
		},
		{
			name:    "no error when pid does not exist",
			spawnFn: nil, // we will use a PID of a process we already waited on
			pidFn:   nil, // set dynamically below
			wantErr: false,
		},
		{
			name:    "no error for pid 0 (ERROR_INVALID_PARAMETER)",
			spawnFn: nil,
			pidFn:   func(_ *exec.Cmd) uint32 { return 0 },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pid uint32

			switch tt.name {
			case "no error when pid does not exist":
				// spawn, wait for it to exit naturally, then use its now-dead PID
				cmd := spawnCmdExe(t)
				pid = uint32(cmd.Process.Pid)
				// kill it via the OS directly so it is gone before we call Kill()
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				// give the OS a moment to fully reap the entry
				time.Sleep(50 * time.Millisecond)

			default:
				var cmd *exec.Cmd
				if tt.spawnFn != nil {
					cmd = tt.spawnFn(t)
				}
				if tt.pidFn != nil {
					pid = tt.pidFn(cmd)
				}
			}

			err := Kill(pid)

			if tt.wantErr && err == nil {
				t.Fatalf("expected an error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// For the live-process case, confirm the process is actually gone
			if tt.name == "kills a live cmd.exe process" {
				assertProcessGone(t, pid)
			}
		})
	}
}

// spawnCmdExe starts a cmd.exe that idles until killed and registers a
// Cleanup that kills it if the test ends before Kill() is called.
func spawnCmdExe(t *testing.T) *exec.Cmd {
	t.Helper()

	// /K keeps the shell alive; /C "pause" waits indefinitely for input
	cmd := exec.Command("cmd.exe", "/C", "pause")

	// ensure the child does not inherit our console so it truly blocks
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start cmd.exe: %v", err)
	}
	t.Logf("spawned cmd.exe with PID %d", cmd.Process.Pid)

	t.Cleanup(func() {
		// best-effort: silence the error if the process is already gone
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	return cmd
}

// assertProcessGone verifies that the process with the given PID is no longer
// running by attempting to open it with SYNCHRONIZE access.
func assertProcessGone(t *testing.T, pid uint32) {
	t.Helper()

	// poll for up to 2 s because TerminateProcess is asynchronous on Windows
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err != nil {
			// Cannot open → process is gone.
			return
		}

		// process handle is still openable; wait up to 100 ms for it to exit
		result, waitErr := windows.WaitForSingleObject(handle, 100)
		_ = windows.CloseHandle(handle)

		if waitErr == nil && result == windows.WAIT_OBJECT_0 {
			return // process exited
		}
	}

	// try to find it in the process list via os.FindProcess
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return // not found → gone
	}
	// FindProcess always succeeds, so send signal 0 as a liveness probe
	if signalErr := proc.Signal(os.Signal(nil)); signalErr != nil {
		return // couldn't signal → gone
	}

	t.Errorf("process %d is still running after Kill()", pid)
}
