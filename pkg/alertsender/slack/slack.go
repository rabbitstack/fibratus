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

package slack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"io"
	"net"
	"net/http"
	"time"
)

const botName = "fibratus"

type slack struct {
	client *http.Client
	config Config
}

// attachment represents Slack attachment info
type attachment struct {
	Fallback string   `json:"fallback"`
	Color    string   `json:"color"`
	Text     string   `json:"text"`
	Mdin     []string `json:"mrkdwn_in"`
}

func init() {
	alertsender.Register(alertsender.Slack, makeSender)
}

// makeSender constructs a new instance of the Slack alert sender.
func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	c, ok := config.Sender.(Config)
	if !ok {
		return nil, alertsender.ErrInvalidConfig(alertsender.Slack)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	return &slack{config: c, client: client}, nil
}

func (s slack) Send(alert alertsender.Alert) error {
	var color string
	switch alert.Severity {
	case alertsender.Medium:
		color = "warning"
	case alertsender.Critical, alertsender.High:
		color = "danger"
	default:
		color = "good"
	}

	text := fmt.Sprintf("%s\n%s", alert.Title, alert.Text)

	attach := attachment{
		Fallback: text,
		Text:     text,
		Color:    color,
		Mdin:     []string{"text"},
	}

	params := make(map[string]interface{})
	params["as_user"] = false
	params["channel"] = s.config.Channel
	params["text"] = ""
	params["attachments"] = []attachment{attach}
	params["username"] = botName
	if s.config.BotEmoji != "" {
		params["icon_emoji"] = s.config.BotEmoji
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	err := enc.Encode(params)
	if err != nil {
		return nil
	}
	//nolint:noctx
	resp, err := s.client.Post(s.config.URL, "application/json", &body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		type response struct {
			Error string `json:"error"`
		}
		r := &response{Error: fmt.Sprintf("failed to send alert to Slack. code: %d content: %s", resp.StatusCode, string(body))}
		b := bytes.NewReader(body)
		dec := json.NewDecoder(b)
		if err := dec.Decode(r); err != nil {
			return err
		}
		return errors.New(r.Error)
	}
	return nil
}

func (s slack) Type() alertsender.Type { return alertsender.Slack }
func (s slack) Shutdown() error        { return nil }
func (s slack) SupportsMarkdown() bool { return true }
