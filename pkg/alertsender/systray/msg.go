//go:build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package systray

import (
	"encoding/json"
	"fmt"
)

const (
	// systrayPipe is the named pipe served by the process that hosts the systray
	// alert sender.
	systrayPipe = `\\.\pipe\fibratus-systray`

	// maxMsgSize is the upper bound on the size of a single encoded message.
	// It protects both ends of the pipe from buffering unbounded input.
	maxMsgSize = 64 << 10

	// maxTitleLen and maxTextLen bound the notification fields, in runes. The
	// shell truncates balloon titles to 63 and bodies to 255 UTF-16 code units,
	// so there is no point in shipping more than a small multiple of that.
	maxTitleLen = 128
	maxTextLen  = 512
)

// MsgType determines the type of the message sent to the systray clients.
type MsgType uint8

const (
	// Conf carries the Settings the client applies to the notifications it shows.
	Conf MsgType = iota
	// Balloon carries the Notification the client renders as a balloon.
	Balloon
)

// Msg is the envelope exchanged over the systray pipe. Messages flow in a single
// direction, from the alert sender to the client, and are framed as one JSON
// document per line.
type Msg struct {
	Type MsgType         `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Decode unmarshals the message payload into out.
func (m Msg) Decode(out any) error {
	return json.Unmarshal(m.Data, out)
}

// Settings are the presentation options pushed to the client right after it connects.
type Settings struct {
	// Sound indicates if the associated sound is played when the balloon is shown.
	Sound bool `json:"sound"`
	// QuietMode instructs not to display the balloon if the user is in quiet time.
	QuietMode bool `json:"quiet_mode"`
}

// Notification is the final text the client renders in the balloon. The alert
// is deliberately reduced to what is displayed so that events, labels, command
// lines and other alert context never cross the pipe.
type Notification struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

// encodeMsg serializes the message payload and frames it with a trailing new line.
// The JSON encoder escapes control characters inside strings, so a new line can
// never appear within a frame.
func encodeMsg(typ MsgType, data any) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(Msg{Type: typ, Data: raw})
	if err != nil {
		return nil, err
	}
	if len(b) >= maxMsgSize {
		return nil, fmt.Errorf("systray message of %d bytes exceeds the %d bytes limit", len(b), maxMsgSize)
	}
	return append(b, '\n'), nil
}

// truncate shortens the string to at most n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
