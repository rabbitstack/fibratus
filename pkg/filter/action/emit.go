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

package action

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/renderer"
	"github.com/rabbitstack/fibratus/pkg/config"
	log "github.com/sirupsen/logrus"
)

// Emit sends the rule alert via all configured alert senders.
func Emit(ctx *config.ActionContext, title string, text string, args ...string) error {
	log.Debugf("sending alert: %s. Text: %s", title, text)

	senders := alertsender.FindAll()
	if len(senders) == 0 {
		return fmt.Errorf("no alertsenders registered. Alert won't be sent")
	}

	severity := "medium"
	tags := make([]string, 0)
	if len(args) > 0 {
		severity = args[0]
	}
	if len(args) > 1 {
		tags = args[1:]
	}

	for _, s := range senders {
		alert := alertsender.NewAlert(
			title,
			text,
			tags,
			alertsender.ParseSeverityFromString(severity),
		)
		// produce HTML rule alert text for email sender
		if s.Type() == alertsender.Mail {
			var err error
			alert.Text, err = renderer.RenderHTMLRuleAlert(ctx, alert)
			if err != nil {
				log.Warn(err)
			}
		}
		go func(s alertsender.Sender) {
			if err := s.Send(alert); err != nil {
				log.Warnf("unable to emit alert from rule: %v", err)
			}
		}(s)
	}
	return nil
}
