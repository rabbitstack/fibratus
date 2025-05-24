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

package elasticsearch

import (
	"bytes"
	"context"
	"fmt"
	"github.com/olivere/elastic/v7"
	"github.com/rabbitstack/fibratus/pkg/event"
	"html/template"
	"strings"
	"time"
)

type index struct {
	config Config
	client *elastic.Client
}

// putTemplate creates the index template.
func (i index) putTemplate() error {
	if i.config.TemplateName == "" {
		return nil
	}
	// get the index pattern for the template
	indexPattern := i.config.IndexName
	if strings.Contains(indexPattern, "%") {
		indexPattern = indexPattern[0:strings.Index(indexPattern, "%")]
	}

	var b bytes.Buffer
	if i.config.TemplateConfig != "" {
		b.WriteString(i.config.TemplateConfig)
	} else {
		// expand the Go template
		tmpl := template.Must(template.New("template").Parse(indexTemplate))
		err := tmpl.Execute(&b, templateInfo{IndexPattern: indexPattern + "*"})
		if err != nil {
			return err
		}
	}

	ctx := context.Background()

	exists, err := i.client.IndexTemplateExists(i.config.TemplateName).Do(ctx)
	if err != nil {
		return fmt.Errorf("unable to check the existence of the %q template: %v", i.config.TemplateName, err)
	}
	if exists {
		return nil
	}
	// create index template
	_, err = i.client.IndexPutTemplate(i.config.TemplateName).BodyJson(b.String()).Do(ctx)
	if err != nil {
		return fmt.Errorf("unable to create index for the %q template: %v", i.config.TemplateName, err)
	}

	return nil
}

// getName creates an index name by replacing specifiers to create time frame indices. If no time specifiers are
// used this method returns a fixed index name.
func (i index) getName(evt *event.Event) string {
	indexName := i.config.IndexName
	if !strings.Contains(indexName, "%") {
		return indexName
	}
	return i.replace(evt.Timestamp)
}

func (i index) replace(timestamp time.Time) string {
	return strings.NewReplacer(
		"%Y", timestamp.UTC().Format("2006"),
		"%y", timestamp.UTC().Format("06"),
		"%m", timestamp.UTC().Format("01"),
		"%d", timestamp.UTC().Format("02"),
		"%H", timestamp.UTC().Format("15")).Replace(i.config.IndexName)
}
