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

package stats

import (
	"encoding/json"
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"os"
	"reflect"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/pkg/config"
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/util/rest"
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "stats",
	Short: "Show runtime stats",
	RunE:  stats,
}

var cfg = config.NewWithOpts(config.WithStats())

func init() {
	cfg.MustViperize(Command)
}

// Stats stores runtime statistics that are retrieved from the expvar endpoint.
type Stats struct {
	AggregatorBatchEvents               int            `json:"aggregator.batch.events"`
	AggregatorFlushesCount              int            `json:"aggregator.flushes.count"`
	AggregatorEventErrors               int            `json:"aggregator.event.errors"`
	AggregatorTransformerErrors         map[string]int `json:"aggregator.transformer.errors"`
	AggregatorWorkerClientPublishErrors int            `json:"aggregator.worker.client.publish.errors"`
	FilamentDictErrors                  int            `json:"filament.dict.errors"`
	FilamentEventBatchFlushes           int            `json:"filament.event.batch.flushes"`
	FilamentEventErrors                 map[string]int `json:"filament.event.errors"`
	FilamentEventProcessErrors          int            `json:"filament.event.process.errors"`
	FilterAccessorErrors                map[string]int `json:"filter.accessor.errors"`
	FsFileObjectHandleHits              int            `json:"fs.file.object.handle.hits"`
	FsFileObjectMisses                  int            `json:"fs.file.object.misses"`
	FsFileReleases                      int            `json:"fs.file.releases"`
	FsTotalRundownFiles                 int            `json:"fs.total.rundown.files"`
	HandleDeferredEvictions             int            `json:"handle.deferred.evictions"`
	HandleNameQueryFailures             map[string]int `json:"handle.name.query.failures"`
	HandleSnapshotCount                 int            `json:"handle.snapshot.count"`
	HandleSnapshotBytes                 int            `json:"handle.snapshot.bytes"`
	HandleTypesCount                    int            `json:"handle.types.count"`
	HandleTypeNameMisses                int            `json:"handle.type.name.misses"`
	HandleWaitTimeouts                  int            `json:"handle.wait.timeouts"`
	HostnameErrors                      map[string]int `json:"hostname.errors"`
	CapFlusherErrors                    map[string]int `json:"cap.flusher.errors"`
	CapHandleWriteErrors                int            `json:"cap.handle.write.errors"`
	CapEventUnmarshalErrors             int            `json:"cap.event.unmarshal.errors"`
	CapEventWriteErrors                 int            `json:"cap.event.write.errors"`
	CapEventSourceConsumerErrors        int            `json:"cap.eventsource.consumer.errors"`
	CapOverflowErrors                   int            `json:"cap.overflow.errors"`
	CapReadBytes                        int            `json:"cap.read.bytes"`
	CapReadEvents                       int            `json:"cap.read.events"`
	CapReaderDroppedByFilter            int            `json:"cap.reader.dropped.by.filter"`
	CapReaderHandleUnmarshalErrors      int            `json:"cap.reader.handle.unmarshal.errors"`
	EventProcessorFailures              int            `json:"event.processor.failures"`
	EventSeqInitErrors                  map[string]int `json:"event.seq.init.errors"`
	EventSeqStoreErrors                 int            `json:"event.seq.store.errors"`
	EventTimestampUnmarshalErrors       int            `json:"event.timestamp.unmarshal.errors"`
	EventSourceBuffersRead              int            `json:"eventsource.buffers.read"`
	EventSourceEventsEnqueued           int            `json:"eventsource.events.enqueued"`
	EventSourceEventsDequeued           int            `json:"eventsource.events.dequeued"`
	EventSourceUnknownEvents            int            `json:"eventsource.events.unknown"`
	EventSourceEventsProcessed          int            `json:"eventsource.events.processed"`
	EventSourceExcludedEvents           int            `json:"eventsource.excluded.events"`
	EventSourceEventsFailures           map[string]int `json:"eventsource.events.failures"`
	LoggerErrors                        map[string]int `json:"logger.errors"`
	OutputAMQPChannelFailures           int            `json:"output.amqp.channel.failures"`
	OutputAMQPConnectionFailures        int            `json:"output.amqp.connection.failures"`
	OutputAMQPPublishErrors             int            `json:"output.amqp.publish.errors"`
	OutputConsoleErrors                 int            `json:"output.console.errors"`
	OutputNullBlackholeEvents           int            `json:"output.null.blackhole.events"`
	PeSkippedImages                     int            `json:"pe.skipped.images"`
	PeDirectoryParseErrors              int            `json:"pe.directory.parse.errors"`
	PeVersionResourcesParseErrors       int            `json:"pe.version.resources.parse.errors"`
	ProcessCount                        int            `json:"process.count"`
	ProcessModuleCount                  int            `json:"process.module.count"`
	ProcessLookupFailureCount           map[int]int    `json:"process.lookup.failure.count"`
	ProcessPebReadErrors                int            `json:"process.peb.read.errors"`
	ProcessReaped                       int            `json:"process.reaped"`
	ProcessThreadCount                  int            `json:"process.thread.count"`
	RegistryKcbCount                    int            `json:"registry.kcb.count"`
	RegistryKcbMisses                   int            `json:"registry.kcb.misses"`
	RegistryKeyHandleHits               int            `json:"registry.key.handle.hits"`
	RegistryUnknownKeysCount            int            `json:"registry.unknown.keys.count"`
	StackwalkEnqueued                   int            `json:"stackwalk.enqueued"`
	StackwalkFlushes                    int            `json:"stackwalk.flushes"`
	StackwalkFlushesProcs               map[string]int `json:"stackwalk.flushes.procs"`
	StackwalkFlushesEvents              map[string]int `json:"stackwalk.flushes.events"`
	YaraImageScans                      int            `json:"yara.image.scans"`
	YaraProcScans                       int            `json:"yara.proc.scans"`
	YaraRuleMatches                     int            `json:"yara.rule.matches"`
}

func stats(cmd *cobra.Command, args []string) error {
	if err := bootstrap.InitConfigAndLogger(cfg); err != nil {
		return err
	}
	c := cfg.API
	body, err := rest.Get(rest.WithTransport(c.Transport), rest.WithURI("debug/vars"))
	if err != nil {
		return errs.ErrHTTPServerUnavailable(c.Transport, err)
	}
	var stats Stats
	if err := json.Unmarshal(body, &stats); err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Value"})
	t.SetStyle(table.StyleLight)

	typ := reflect.TypeOf(stats)
	val := reflect.ValueOf(stats)

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")

		if tag == "" {
			continue
		}
		if !val.Field(i).CanInterface() {
			continue
		}
		t.AppendRow(table.Row{tag, val.Field(i).Interface()})
	}

	t.Render()

	return nil
}
