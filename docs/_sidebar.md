* Setup
  * [Installation](setup/installation.md)
  * [Quick Start](setup/quick-start.md)
  * [Configuration](setup/configuration.md)
* ---
* [Architecture](architecture.md)
* ---
* Telemetry
  * [Events](telemetry/events/anatomy.md)
    * [Process](telemetry/events/process.md)
    * [Thread](telemetry/events/thread.md)
    * [Module](telemetry/events/module.md)
    * [File](telemetry/events/file.md)
    * [Registry](telemetry/events/registry.md)
    * [Memory](telemetry/events/mem.md)
    * [Network](telemetry/events/network.md)
    * [Handle](telemetry/events/handle.md)
    * [Object](telemetry/events/object.md)
  * Callstacks
  * Evasions
  * Filtering
  * Outputs
    * [Transporting Events](telemetry/outputs/introduction.md)
    * [Console](telemetry/outputs/console.md)
    * [Null](telemetry/outputs/null.md)
    * [RabbitMQ](telemetry/outputs/rabbitmq.md)
    * [Elasticsearch](telemetry/outputs/elasticsearch.md)
    * [HTTP](telemetry/outputs/http.md)
    * [Eventlog](telemetry/outputs/eventlog.md)
  * Transformers
    * [Parsing, Enriching, Transforming](telemetry/transformers/introduction.md)
    * [Remove](telemetry/transformers/remove.md)
    * [Rename](telemetry/transformers/rename.md)
    * [Replace](telemetry/transformers/replace.md)
    * [Trim](telemetry/transformers/trim.md)
    * [Tags](telemetry/transformers/tags.md)
* Rule Language
  * [Needle In The Haystack](rulelang/filters/introduction.md)
  * [Filtering](rulelang/filters/filtering.md)
  * [Operators](rulelang/filters/operators.md)
  * [Iterators](rulelang/filters/iterators.md)
  * [Functions](rulelang/filters/functions.md)
  * [Rules](rulelang/filters/rules.md)
  * [Fields](rulelang/filters/fields.md)
  * Actions
    * Alerts
      * [Firing Alerts](rulelang/actions/alerts/introduction.md)
      * [Alert Senders](rulelang/actions/alerts/senders.md)
      * [Mail](rulelang/actions/alerts/senders/mail.md)
      * [Slack](rulelang/actions/alerts/senders/slack.md)
      * [Systray](rulelang/actions/alerts/senders/systray.md)
      * [Eventlog](rulelang/actions/alerts/senders/eventlog.md)
    * Kill
    * Isolate
  * PE
    * [Portable Executable Introspection](/pe/introduction.md)
    * [Sections](/pe/sections.md)
    * [Symbols](/pe/symbols.md)
    * [Resources](/pe/resources.md)
* ---
* Captures
  * [Immortalizing The Event Flux](captures/introduction.md)
  * [Capturing](captures/capturing.md)
  * [Replaying](captures/replaying.md)
* Filaments
  * [Python Meets Kernel Events](filaments/introduction.md)
  * [Executing](filaments/executing.md)
  * [Internals](filaments/internals.md)
  * [Writing Filaments](filaments/writing.md)
  * [Alerting](alerts/filaments.md)
* YARA
  * [Pattern Matching Swiss Knife](/yara/introduction.md)
  * [Scanning Processes](/yara/scanning.md)
  * [Alerts](/yara/alerts.md)
* ---
* Troubleshooting
  * [Logs](troubleshooting/logs.md)
  * [Stats](troubleshooting/stats.md)
  * [Profiling](troubleshooting/pprof.md)
* [CLI](cli.md)
