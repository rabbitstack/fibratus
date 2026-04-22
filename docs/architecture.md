# Architecture

##### The diagram illustrates the end-to-end runtime threat detection pipeline allowing Fibratus to unveil and neutralize stealthy  attack chains.

![Architecture](images/architecture.png "Architecture")

### Event Sources

The leftmost block represents the Windows host machine and the kernel instrumentation layer that feeds all telemetry into **Fibratus**.
The Windows host exposes kernel-level telemetry through the [Event Tracing for Windows](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/event-tracing-for-windows) subsystem - a high-performance, always-on tracing infrastructure built into the Windows NT kernel. Fibratus subscribes to ETW system providers as a realtime consumer, receiving a continuous stream of  kernel events without requiring a kernel driver of its own. Fibratus captures a wide-spectrum of system events:


- [Process](telemetry/events/process): process creation, termination, and process object access
- [Thread](telemetry/events/thread): thread creation, termination, thread pool activity, thread object access and thread context manipulation
- [File](telemetry/eventss/file): file I/O operations including reads, writes, creates, deletions, file metadata manipulation and renames
- [Memory](telemetry/events/mem.md): virtual memory allocation and section mapping/unmapping
- [Network](telemetry/events/network.md): low level network operations such as TCP/UDP send and receive, connect and accept events
- [Registry](telemetry/events/registry.md): key creation, deletion, access, and value mutation
- [Module](telemetry/events/module.md): DLL/executable/driver load and unload events
- [DNS](telemetry/events/network.md): DNS query and response telemetry
- [Handle](telemetry/events/handle.md): object handle creation and duplication


### Event Pipeline

Once raw ETW events are ingested, they pass through a two-stage pipeline before reaching the engine.

##### Collection

The **Collection** stage is responsible for receiving, parsing, and normalising raw ETW event records. Each event is deserialised from its binary ETW wire format into a structured internal event representation. Field extraction, type coercion, and sequence assembly happen here, turning low-level kernel signals into richly typed, queryable event objects ready for downstream processing.

##### Enrichment

The **Enrichment** stage decorates each event with contextual metadata that is not present in the raw ETW record but is essential for detection. This includes:

**Process context injection**. The full [process state](telemetry/events/process.md) for the event's originating process is attached, including executable path, command-line arguments, user, session, token integrity level, process modules, and so on.

**Parent process tree traversal**. The ancestry chain is resolved from live process snapshot cache, allowing rules to reason about parent-child relationships.

**Callstack resolution**. Return addresses captured at event time are resolved against loaded module symbols, producing human-readable [callstack frames](telemetry/callstacks.md) that reveal the code path that triggered the event.

**PE metadata enrichment**. Portable executable attributes such as digital signature status, entropy, and import table characteristics are attached where available.

The process snapshot and process tree cache serves as the authoritative in-memory state for all enrichment lookups, ensuring sub-microsecond context resolution.

##### Rule Engine and Memory Scanner

After enrichment, each event is dispatched simultaneously to two parallel evaluators. **Rule Engine** evaluates the enriched event against the loaded detection rule set. [Rules](rules.md) are expressed in a behaviour-driven `YAML` DSL (Domain Specific Language) and compiled into an optimised filter/expression tree at startup. The rule engine supports boolean and sequence operators for multi-event correlation, field accessor expressions with full type awareness, pattern matching, glob expressions, IP/CIDR predicates and stateful sequence tracking for multi-step attack pattern detection. When a rule condition matches, the engine generates an alert and apply response actions such as terminating the process.

**Memory Scanner** runs in parallel and is triggered on arrival of different signals such as suspiciuous memory allocations, section mappings or unsigned DLL loading. It performs [YARA](yara.md) rule scanning of process virtual memory, enabling detection of injected shellcode, unpacked malware, and in-memory IOCs that leave no filesystem artefact.

### Outputs

[Outputs](telemetry/outputs.md) consists of three branches that operate independently and can all fire simultaneously for a single matched event.

##### Alert

Is triggered when the rule engine or memory scanner produces a security alert. It dispatches a structured alert object containing the rule name, severity, [MITRE](https://attack.mitre.org/) tactic and technique tags, process metadata, and a callstack excerpt to one or more configured [alert senders](rules/actions/alert.md) such as Slack, Email or Eventlog.

##### Send

Streams every matched event to persistent storage or message broker infrastructure for retention, search, and downstream analytics. The event can be forwarded to [Elasticsearch](telemetry/outputs/elasticsearch.md), [RabbitMQ](telemetry/outputs/rabbitmq.md) message broker, [HTTP](telemetry/outputs/http.md) endpoints, or [console](telemetry/outputs/console.md) for local analysis.

##### Actuate

Executes protective response [actions](rules/actions.md) in direct response to a rule match. Response actions include killing the offending process or isolating the host by cutting off its ability to communicate with internal or external networks while preserving forensic state for investigation.
