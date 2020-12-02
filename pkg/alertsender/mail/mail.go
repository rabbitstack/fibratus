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

package mail

import (
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"gopkg.in/gomail.v2"
)

type mail struct {
	dialer *gomail.Dialer
	c      Config
}

func init() {
	alertsender.Register(alertsender.Mail, makeSender)
}

// makeSender constructs a new instance of the email alert sender.
func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	c, ok := config.Sender.(Config)
	if !ok {
		return nil, alertsender.ErrInvalidConfig(alertsender.Mail)
	}
	dialer := gomail.NewDialer(c.Host, c.Port, c.User, c.Pass)
	return &mail{dialer: dialer, c: c}, nil
}

func (s mail) Send(alert alertsender.Alert) error {
	sender, err := s.dialer.Dial()
	if err != nil {
		return err
	}
	defer sender.Close()
	return gomail.Send(sender, composeMessage(s.c.From, s.c.To, alert))
}

func composeMessage(from string, to []string, alert alertsender.Alert) *gomail.Message {
	msg := gomail.NewMessage()
	msg.SetHeader("From", from)
	msg.SetHeader("To", to...)
	msg.SetHeader("Subject", alert.Title)
	msg.SetBody("text/plain", alert.Text)
	return msg
}
