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
	"github.com/rabbitstack/fibratus/pkg/util/markdown"
	log "github.com/sirupsen/logrus"
)

// Emit sends the rule alert via all configured alert senders.
func Emit(ctx *config.ActionContext, title string, text string, severity string, tags []string) error {
	log.Infof("sending alert: [%s]. Text: %s", title, text)

	senders := alertsender.FindAll()
	if len(senders) == 0 {
		return fmt.Errorf("no alertsenders registered. Alert won't be sent")
	}

	for _, sender := range senders {
		alert := alertsender.NewAlert(
			title,
			text,
			tags,
			alertsender.ParseSeverityFromString(severity),
		)
		// strip markdown
		if !sender.SupportsMarkdown() {
			alert.Text = markdown.Strip(alert.Text)
		}
		// produce HTML rule alert text for email sender
		if sender.Type() == alertsender.Mail {
			var err error
			alert.Text, err = renderer.RenderHTMLRuleAlert(ctx, alert)
			if err != nil {
				return err
			}
		}
		err := sender.Send(alert)
		if err != nil {
			return fmt.Errorf("unable to emit alert from rule via [%s] sender: %v", sender.Type(), err)
		}
	}
	return nil
}
