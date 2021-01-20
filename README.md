---

<p align="center" >
  <a href="https://www.fibratus.io" >
    <img src="logo.png" alt="Fibratus">
  </a>
</p>

<h2 align="center">Fibratus</h2>

<p align="center">
  A modern tool for the Windows kernel exploration and observability
  <br>
  <a href="https://www.fibratus.io/#/setup/installation"><strong>Get Started »</strong></a>
  <br>
  <br>
  <strong>
    <a href="https://www.fibratus.io/#/setup/installation">Docs</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/tree/master/filaments">Filaments</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/releases">Download</a>
  </strong>
</p>

### What is Fibratus?

Fibratus is a tool for exploration and tracing of the **Windows** kernel. It lets you trap system-wide [events](https://www.fibratus.io/#/kevents/anatomy) such as process life-cycle, file system I/O, registry modifications or network requests among many other observability signals. In a nutshell, Fibratus allows for gaining deep operational visibility into the Windows kernel but also processes running on top of it.

Events can be shipped to a wide array of [output sinks](https://www.fibratus.io/#/outputs/introduction) or dumped to [capture](https://www.fibratus.io/#/captures/introduction) files for local inspection and forensics analysis. The powerful [filtering](https://www.fibratus.io/#/filters/introduction) engine permits drilling into the event flux entrails.

You can use [filaments](https://www.fibratus.io/#/filaments/introduction) to extend Fibratus with your own arsenal of tools and so leverage the power of the Python ecosystem.

### Features

- :zap: blazing fast
- :satellite: collects a wide spectrum of kernel events - from process to network observability signals
- :mag: super powerful filtering engine
- :snake: running Python scriptlets on top of kernel event flow
- :minidisc: capturing event flux to **kcap** files and replaying anywhere
- :rocket: transporting events to Elasticsearch, RabbitMQ or console sinks
- :scissors: transforming kernel events
- :beetle: scanning malicious processes and files with Yara
- :file_folder: PE (Portable Executable) introspection

### [Documentation](https://www.fibratus.io)
---

### Setup

* [**Installation**](https://www.fibratus.io/#/setup/installation)
* [**Building from source**](https://www.fibratus.io/#/setup/installation?id=building-from-source)
* [**Running as standalone binary**](https://www.fibratus.io/#/setup/running?id=standalone-binary)
* [**Running as Windows Service**](https://www.fibratus.io/#/setup/running?id=windows-service)
* [**CLI**](https://www.fibratus.io/#/setup/running?id=cli)
* [**Configuration**](https://www.fibratus.io/#/setup/configuration)

### Events

* [**Anatomy of an event**](https://www.fibratus.io/#/kevents/anatomy)
* [**Process**](https://www.fibratus.io/#/kevents/process)
* [**Thread**](https://www.fibratus.io/#/kevents/thread)
* [**Image**](https://www.fibratus.io/#/kevents/image)
* [**File**](https://www.fibratus.io/#/kevents/file)
* [**Registry**](https://www.fibratus.io/#/kevents/registry)
* [**Network**](https://www.fibratus.io/#/kevents/network)
* [**Handle**](https://www.fibratus.io/#/kevents/handle)

### Filters

* [**Needle in the haystack**](https://www.fibratus.io/#/filters/introduction)
* [**Prefiltering**](https://www.fibratus.io/#/filters/prefiltering)
* [**Filtering**](https://www.fibratus.io/#/filters/filtering)
* [**Operators**](https://www.fibratus.io/#/filters/operators)
* [**Fields**](https://www.fibratus.io/#/filters/fields)

### Captures

* [**Immortalizing the event flux**](https://www.fibratus.io/#/captures/introduction)
* [**Capturing**](https://www.fibratus.io/#/captures/capturing)
* [**Replaying**](https://www.fibratus.io/#/captures/replaying)

### Filaments

* [**Python meets kernel events**](https://www.fibratus.io/#/filaments/introduction)
* [**Executing**](https://www.fibratus.io/#/filaments/executing)
* [**Internals**](https://www.fibratus.io/#/filaments/internals)
* [**Writing filaments**](https://www.fibratus.io/#/filaments/writing)

### Outputs

* [**Transporting kernel events**](https://www.fibratus.io/#/outputs/introduction)
* [**Console**](https://www.fibratus.io/#/outputs/console)
* [**Null**](https://www.fibratus.io/#/outputs/null)
* [**RabbitMQ**](https://www.fibratus.io/#/outputs/rabbitmq)
* [**Elasticsearch**](https://www.fibratus.io/#/outputs/elasticsearch)


### Transformers

* [**Parsing, enriching, transforming**](https://www.fibratus.io/#/transformers/introduction)
* [**Remove**](https://www.fibratus.io/#/transformers/remove)
* [**Rename**](https://www.fibratus.io/#/transformers/rename)
* [**Replace**](https://www.fibratus.io/#/transformers/replace)
* [**Tags**](https://www.fibratus.io/#/transformers/tags)
* [**Trim**](https://www.fibratus.io/#/transformers/trim)

### Alerts

* [**Watchdogging kernel events**](https://www.fibratus.io/#/alerts/introduction)
* [**Mail**](https://www.fibratus.io/#/alerts/senders/mail)
* [**Slack**](https://www.fibratus.io/#/alerts/senders/slack)
* [**Filament alerting**](https://www.fibratus.io/#/alerts/filaments)

### PE (Portable Executable)

* [**Portable Executable introspection**](https://www.fibratus.io/#/pe/introduction)
* [**Sections**](https://www.fibratus.io/#/pe/sections)
* [**Symbols**](https://www.fibratus.io/#/pe/symbols)
* [**Resources**](https://www.fibratus.io/#/pe/resources)

### YARA

* [**Pattern matching swiss knife**](https://www.fibratus.io/#/yara/introduction)
* [**Scanning processes**](https://www.fibratus.io/#/yara/scanning)
* [**Alerts**](https://www.fibratus.io/#/yara/alerts)

### Troubleshooting

* [**Logs**](https://www.fibratus.io/#/troubleshooting/logs)
* [**Stats**](https://www.fibratus.io/#/troubleshooting/stats)
* [**Profiling**](https://www.fibratus.io/#/troubleshooting/pprof)

---

<p align="center">
  Developed with ❤️ by <strong>Nedim Šabić Šabić</strong>
</p>
<p align="center">
  Logo designed with ❤️ by <strong><a name="logo" target="_blank" href="https://github.com/karinkasweet/">Karina Slizova</a></strong>
</p>
