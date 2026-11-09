package eval

import "github.com/rabbitstack/fibratus/pkg/event"

// GetFramePID returns the pid associated with the stack frame.
func GetFramePID(event *event.Event) uint32 {
	if !event.Callstack.IsEmpty() && event.Callstack.FrameAt(0).PID != 0 {
		return event.Callstack.FrameAt(0).PID
	}
	return event.PID
}
