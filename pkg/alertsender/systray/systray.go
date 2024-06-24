/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"github.com/Microsoft/go-winio"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"time"
)

const systrayPipe = `\\.\pipe\fibratus-systray`

// systray interops with the status area
// to show balloon notifications with the
// desired title and text. Both, regular
// and balloon icons are also rendered when
// displaying the notification message. The
// interactions with the status area are
// performed via IPC through named pipe.
// Systray process exposes the named pipe server
// and listen for incoming messages published
// by the systray sender.
type systray struct {
	config Config
	npipe  net.Conn
}

type MsgType uint8

const (
	Conf MsgType = iota
	Balloon
	Shutdown
)

// Msg represents the data exchanged between systray client/server.
type Msg struct {
	Type MsgType `json:"type"`
	Data any     `json:"data"`
}

func (m Msg) encode() ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, err
}

func init() {
	alertsender.Register(alertsender.Systray, makeSender)
}

// makeSender constructs a new instance of the systray alert sender.
func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	c, ok := config.Sender.(Config)
	if !ok {
		return nil, alertsender.ErrInvalidConfig(alertsender.Systray)
	}

	if !c.Enabled {
		return &systray{}, nil
	}

	retries := 20
	for {
		if retries == 0 {
			break
		}
		if !pipeExists() {
			log.Warnf("systray pipe not ready yet. Trying in 1s...")
			time.Sleep(time.Second)
			retries--
			continue
		}
		break
	}

	npipe, err := winio.DialPipe(systrayPipe, nil)
	if err != nil {
		return nil, err
	}

	s := &systray{
		config: c,
		npipe:  npipe,
	}

	return s, s.writePipe(&Msg{Type: Conf, Data: c})
}

func (s systray) Send(alert alertsender.Alert) error {
	m := &Msg{Type: Balloon, Data: alert}
	return s.writePipe(m)
}

func (s systray) Type() alertsender.Type { return alertsender.Systray }
func (s systray) SupportsMarkdown() bool { return false }

func (s systray) Shutdown() error {
	m := &Msg{Type: Shutdown}
	return s.writePipe(m)
}

func (s systray) writePipe(m *Msg) error {
	b, err := m.encode()
	if err != nil {
		return err
	}
	err = s.npipe.SetWriteDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		return err
	}
	n, err := s.npipe.Write(b)
	if n < len(b) {
		return fmt.Errorf("write I/O error: buffer size: %d written: %d", len(b), n)
	}
	return err
}

func pipeExists() bool {
	_, err := os.Stat(systrayPipe)
	return err == nil
}
