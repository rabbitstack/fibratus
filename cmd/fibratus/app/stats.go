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

package app

import (
	"encoding/json"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/cmd/fibratus/common"
	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/util/rest"
	"github.com/spf13/cobra"
	"os"
	"reflect"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show runtime stats",
	RunE:  stats,
}

var statsConfig = config.NewWithOpts(config.WithStats())

func init() {
	statsConfig.MustViperize(statsCmd)
}

// Stats stores runtime statistics that are retrieved from the expvar endpoint.
type Stats struct {
	AggregatorBatchEvents               int            `json:"aggregator.batch.events"`
	AggregatorFlushesCount              int            `json:"aggregator.flushes.count"`
	AggregatorKeventErrors              int            `json:"aggregator.kevent.errors"`
	AggregatorTransformerErrors         map[string]int `json:"aggregator.transformer.errors"`
	AggregatorWorkerClientPublishErrors int            `json:"aggregator.worker.client.publish.errors"`
	FilamentKdictErrors                 int            `json:"filament.kdict.errors"`
	FilamentKeventBatchFlushes          int            `json:"filament.kevent.batch.flushes"`
	FilamentKeventErrors                map[string]int `json:"filament.kevent.errors"`
	FilamentKeventProcessErrors         int            `json:"filament.kevent.process.errors"`
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
	KcapFlusherErrors                   map[string]int `json:"kcap.flusher.errors"`
	KcapHandleWriteErrors               int            `json:"kcap.handle.write.errors"`
	KcapKeventUnmarshalErrors           int            `json:"kcap.kevent.unmarshal.errors"`
	KcapKeventWriteErrors               int            `json:"kcap.kevent.write.errors"`
	KcapKstreamConsumerErrors           int            `json:"kcap.kstream.consumer.errors"`
	KcapOverflowErrors                  int            `json:"kcap.overflow.errors"`
	KcapReadBytes                       int            `json:"kcap.read.bytes"`
	KcapReadKevents                     int            `json:"kcap.read.kevents"`
	KcapReaderDroppedByFilter           int            `json:"kcap.reader.dropped.by.filter"`
	KcapReaderHandleUnmarshalErrors     int            `json:"kcap.reader.handle.unmarshal.errors"`
	KeventInterceptorFailures           int            `json:"kevent.interceptor.failures"`
	KeventSeqInitErrors                 map[string]int `json:"kevent.seq.init.errors"`
	KeventSeqStoreErrors                int            `json:"kevent.seq.store.errors"`
	KeventTimestampUnmarshalErrors      int            `json:"kevent.timestamp.unmarshal.errors"`
	KstreamBlacklistDroppedKevents      map[string]int `json:"kstream.blacklist.dropped.kevents"`
	KstreamBlacklistDroppedProcs        map[string]int `json:"kstream.blacklist.dropped.procs"`
	KstreamKbuffersRead                 int            `json:"kstream.kbuffers.read"`
	KstreamKeventParamFailures          int            `json:"kstream.kevent.param.failures"`
	KstreamKeventsEnqueued              int            `json:"kstream.kevents.enqueued"`
	KstreamKeventsDequeued              int            `json:"kstream.kevents.dequeued"`
	KstreamKeventsFailures              map[string]int `json:"kstream.kevents.failures"`
	KstreamKeventsMissingSchemaErrors   map[string]int `json:"kstream.kevents.missing.schema.errors"`
	KstreamUpstreamCancellations        int            `json:"kstream.upstream.cancellations"`
	LoggerErrors                        map[string]int `json:"logger.errors"`
	OutputAmqpChannelFailures           int            `json:"output.amqp.channel.failures"`
	OutputAmqpConnectionFailures        int            `json:"output.amqp.connection.failures"`
	OutputAmqpPublishErrors             int            `json:"output.amqp.publish.errors"`
	OutputConsoleErrors                 int            `json:"output.console.errors"`
	OutputNullBlackholeEvents           int            `json:"output.null.blackhole.events"`
	PeFailedResourceEntryReads          int            `json:"pe.failed.resource.entry.reads"`
	PeMaxResourceEntriesExceeded        int            `json:"pe.max.resource.entries.exceeded"`
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
	SidsCount                           int            `json:"sids.count"`
	YaraImageScans                      int            `json:"yara.image.scans"`
	YaraProcScans                       int            `json:"yara.proc.scans"`
	YaraRuleMatches                     int            `json:"yara.rule.matches"`
}

func stats(cmd *cobra.Command, args []string) error {
	if err := common.Init(cfg, false); err != nil {
		return err
	}

	c := statsConfig.API
	body, err := rest.Get(rest.WithTransport(c.Transport), rest.WithURI("debug/vars"))
	if err != nil {
		return kerrors.ErrHTTPServerUnavailable(c.Transport, err)
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
