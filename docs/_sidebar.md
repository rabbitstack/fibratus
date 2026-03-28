* Setup
  * [Installation](setup/installation.md)
  * [Quick Start](setup/quick-start.md)
  * [Configuration](setup/configuration.md)
  * [CLI](setup/cli.md)
* ---
* Telemetry
  * Events
    * [Anatomy Of An Event](kevents/anatomy.md)
    * [Process](kevents/process.md)
    * [Thread](kevents/thread.md)
    * [Image](kevents/image.md)
    * [File](kevents/file.md)
    * [Registry](kevents/registry.md)
    * [Network](kevents/network.md)
    * [Handle](kevents/handle.md)
    * [Object](kevents/object.md)
    * [Driver](kevents/driver.md)
    * [Memory](kevents/mem.md)
    * [Configuration](filters/prefiltering.md)
  * Callstacks
  * Transformers
    * [Parsing, Enriching, Transforming](transformers/introduction.md)
    * [Remove](transformers/remove.md)
    * [Rename](transformers/rename.md)
    * [Replace](transformers/replace.md)
    * [Trim](transformers/trim.md)
    * [Tags](transformers/tags.md)
  * Outputs
    * [Transporting Events](outputs/introduction.md)
    * [Console](outputs/console.md)
    * [Null](outputs/null.md)
    * [RabbitMQ](outputs/rabbitmq.md)
    * [Elasticsearch](outputs/elasticsearch.md)
    * [HTTP](outputs/http.md)
    * [Eventlog](outputs/eventlog.md)
* Rule Language
  * [Needle In The Haystack](filters/introduction.md)
  * [Filtering](filters/filtering.md)
  * [Operators](filters/operators.md)
  * [Iterators](filters/iterators.md)
  * [Functions](filters/functions.md)
  * [Rules](filters/rules.md)
  * [Fields](filters/fields.md)
  * Alerts
    * [Firing Alerts](alerts/introduction.md)
    * [Alert Senders](alerts/senders.md)
    * [Mail](alerts/senders/mail.md)
    * [Slack](alerts/senders/slack.md)
    * [Systray](alerts/senders/systray.md)
    * [Eventlog](alerts/senders/eventlog.md)
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
