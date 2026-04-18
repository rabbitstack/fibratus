# Filaments

Here’s a clearer, more complete, and more compelling version of your **Filaments** documentation, with better structure, improved wording, and expanded technical depth.

---

# Filaments

**Filaments** are Fibratus’ extensibility mechanism that allow you to write **custom logic in Python** and execute it on top of the live (or replayed) kernel event stream.

They effectively turn Fibratus into a **programmable security analytics engine**, where you can build anything from simple event processors to complex detection pipelines.

---

## Why filaments?

**Python** is the lingua franca of penetration testers, threat hunters, and SecOps engineers. A vast ecosystem of security tooling already exists in Python.

Filaments let you bring that ecosystem directly into Fibratus.

With filaments, you can:

* Reuse existing Python libraries and tooling
* Build custom detections beyond declarative rules
* Enrich events with external intelligence
* Automate investigations and responses

> 💡 If you can write it in Python, you can run it inside Fibratus.

---

## What is a filament?

A filament is a **Python script executed within Fibratus** that processes the stream of kernel events in real time or during replay.

It has access to:

* Kernel event data (kevt)
* Process metadata (ps.*)
* File, registry, and network context
* Internal Fibratus state

Conceptually, a filament is:

> A user-defined event processor that runs alongside (or instead of) rules.

---

## Execution model

Filaments are executed **on top of the event stream**:

* Each incoming event is passed to the filament
* The filament can inspect, transform, correlate, or act on it
* Logic is entirely user-defined

This makes filaments ideal for:

* Stateful analysis
* Cross-event correlation
* Complex heuristics that are difficult to express in rules

---

## Under the hood

From a technical standpoint:

* Each filament runs as a **fully initialized Python interpreter instance**
* Fibratus embeds **CPython**
* The runtime is bootstrapped via the CPython C API:

  * Interpreter initialization
  * Module loading
  * Function binding

This architecture provides:

* High flexibility
* Full Python compatibility
* Isolation between filaments

---

## Filaments vs rules

Filaments complement — not replace — the rule engine.

| Feature        | Rules               | Filaments                 |
| -------------- | ------------------- | ------------------------- |
| Syntax         | Declarative         | Imperative (Python)       |
| Complexity     | Moderate            | Arbitrary                 |
| Performance    | High                | Depends on implementation |
| State handling | Limited (sequences) | Fully customizable        |
| Extensibility  | Built-in functions  | Full Python ecosystem     |

### When to use rules

* Straightforward detections
* Pattern matching
* Sequence-based correlations

### When to use filaments

* Complex logic or heuristics
* Integration with external systems
* Advanced state tracking
* Custom alerting or response workflows

---

## Example use cases

### Event enrichment

* Query external APIs (e.g., threat intelligence)
* Annotate events with additional metadata

---

### Custom detection logic

* Detect patterns not expressible with sequences
* Build anomaly detection heuristics

---

### Automated response

* Kill suspicious processes
* Trigger alerts or notifications
* Export data to external systems

---

### Data aggregation

* Track statistics over time
* Build behavioral profiles of processes

---

## Running filaments

Filaments can be executed against:

### Live event stream

```bash
$ fibratus run -f my_filament
```

---

### Captured events

```bash
$ fibratus replay -f my_filament -k events
```

This is particularly useful for:

* Testing filament logic
* Replaying known attack scenarios
* Debugging without live systems

---

## Filament structure (conceptual)

While implementation details may vary, most filaments follow a pattern:

```python id="q7k2lp"
def on_event(evt):
    # Process incoming event
    pass
```

Where:

* `evt` represents the kernel event object
* The function is invoked for each event in the stream

Filaments may also:

* Maintain internal state
* Use external libraries
* Emit output or alerts

---

## Performance considerations

Because filaments execute Python code for each event:

* They are generally **slower than native rule evaluation**
* Poorly optimized filaments can impact throughput

### Recommendations

* Avoid heavy computations in hot paths
* Cache results where possible
* Filter early to reduce processing volume
* Use rules for simple pre-filtering, then filaments for deep analysis

---

## Best practices

* Keep filaments **focused and modular**
* Use rules to **narrow down event streams** before processing
* Leverage Python libraries, but be mindful of performance
* Test filaments using **capture replay** before deploying live
* Log or trace selectively to avoid noise

---

## Summary

Filaments unlock the full power of Python inside Fibratus, enabling:

* Unlimited extensibility
* Deep customization of detection and analysis
* Integration with the broader security ecosystem

They are the ideal tool when rule-based detection is not enough and you need **full control over event processing logic**.

---

If you want, I can also add a **minimal working filament example with real Fibratus APIs** (e.g., accessing `ps`, `file`, `registry` fields), which is usually the most helpful starting point for users.



##### **Python** is the lingua franca of pen testers and other **SecOps**-driven individuals. Many security tools are written in Python language.
Wouldn't it be awesome to exploit the arsenal of those tools in Fibratus or build your own tools atop them?

Fibratus incorporates a framework for painlessly extending the functionality and incorporating new features via Python scripts. These scripts are called **filaments**. You can also think of them as extension points with virtually endless possibilities. Whatever you are allowed to craft in Python, you can also implement in filaments.

Filaments are executed on top of kernel event flux and thus they have access to all event's parameters, process state and so on.
From technical perspective, a filament is a full-fledged instance of the Python interpreter. Fibratus interacts with the **CPython** API to bootstrap the interpreter, initialize the module from filament definition, declare functions and other related tasks.

# Internals

Filaments are scheduled as independent Python Virtual Machines and thus they have their own memory and other resources allocated. Fibratus takes as an input a Python module consisting of various functions and converts them into a running instance of the Python interpreter that knows how to process incoming kernel events. It also augments the Python module with numerous functions that permit a filament to interact with alerts and other state exposed by Fibratus.

### Event dispatching 

The backbone of a filament is the `on_next_kevent` function. It's executed whenever a new kernel event arrives. The parameter of this function is the Python dictionary that contains event data. Here is the structure of such a dictionary object:

```python
{
  'seq': 122344,
  'pid': 2034,
  'tid': 2453,
  'ppid': 45,
  'cwd': 'C:\Windows\system32',
  'exe': 'cmd.exe',
  'comm': 'cmd.exe rm /r',
  'sid': 'archrabbit\SYSTEM',
  'cpu': 2,
  'name': 'CreateFile',
  'category': 'file',
  'timestamp': '2013-08-23 16:15:13.4323',
  'host': 'archrabbit',
  'description': 'Creates or opens a file or I/O device',
  'kparams': {
    'file_name': 'C:\WINDOWS\system32\config\systemprofile\AppData\WindowsApps\',
    'file_object': 'ffffa88c7ea077d0',
    'irp': 'ffffa88c746b2a88',
    'operation': 'supersede',
    'share_mask': 'rw-',
    'type': 'directory'
  }
}
```

For a more convenient dictionary accesses, you can annotate the function with the `dotdictify` decorator.

```python
from utils.dotdict import dotdictify

@dotdictify
def on_next_kevent(kevent):
    print(f'{kevent.name} generated by {kevent.exe}')
```

### Initialization 

If the `on_init` function is declared in the filament, any logic wrapped inside this function is executed prior to event processing. This is a convenient place for configuring the table columns or establishing the `on_interval` function triggering intervals among other initialization tasks.

```python
def on_init():
    interval(1)
```

### Termination 

The `on_stop` function is called right before the Python interpreter is teared down. You can place any code you would like to get executed when the filament is stopped.

```python
def on_stop():
    f.close()
```

### Periodical actions 

Filament has built-in support for scheduling timers. The timer, associated with the `on_interval` function, is fired after the interval specified by the `interval` function elapses. The minimum interval granularity is one second.

```python
def on_interval():
    for ip, count in __connections__.copy().items():
      f.write(f'{ip.count}')
```

### Filtering 

The `kfilter` function defines a filter expression for the life span of a filament. Filaments give an appealing approach for constructing the filters dynamically. For example, this following code snippet defines a filter from the list:

```python
kfilter("ps.name in (%s)" % (', '.join([f'\'{ps}\'' for ps in __procs__])))
```

### Table rendering 

Filaments are able to render tabular data on the console in a flicker-free fashion by using the frame buffers. To render a table, you start by defining the columns with the `columns` function. It's possible to sort the data by specifying the column via `sort_by` function. Finally, the `add_row` function appends rows to the table. When you're ready to draw the table, invoke the `render_table` function.

```python
def on_init():
    columns(["Source", "Count"])
    sort_by('Count')
    interval(1)

def on_interval():
    for ip, count in __connections__.copy().items():
        add_row([ip, count])
    render_table()
```

### Python distribution and pip 

Fibratus bundles embedded Python 3.7 distribution. Installing additional packages can be achieved by running the `pip` command from the `%PROGRAM FILES%\Fibratus\Python\Scripts` directory.




# Executing Filaments

Filaments are bootstrapped via the `fibratus run` command by specifying the filament name. Use the `-f` or `--filament.name` flags to indicate the filament you'd like to run.

```
$ fibratus run -f watch_files
```

The filament will keep running until the keyboard interrupt signal is received. 

### Passing arguments to filaments 

Filaments may require additional arguments to execute some conditional logic or set up a filter. Arguments are passed to a filament by specifying a list of comma-separated values after filament name:

```
$ fibratus run -f "watch_files,powershell.exe"
```

This populates the [sys.argv](https://docs.python.org/3/library/sys.html#sys.argv) list with the provided arguments, where `sys.argv[0]` is the filament name.


### Listing filaments 

By default, filaments reside within the `%PROGRAMFILES%\Fibratus\Filaments` directory. It is possible to override this location by specifying an alternative directory via the `--filament.path` flag or by editing the config file.

To list available filaments, run the below command.

```
$ fibratus list filaments
```

### Filters 

Engaging filters in filaments can be accomplished in two ways:

- the command line argument when running the filament
- the `kfilter` function during filament initialization

If the filter expression is supplied in both the CLI argument and the `kfilter` function, the one set in the latter takes precedence.

# Writing Filaments

The best way to grasp filaments is by writing a new filament from scratch. The following is the walkthrough of building a filament that fetches the IP blacklist database and relies on it to detect outbound/inbound connections to botnets, C&C servers, and other fishy destinations.

Let's first define the function for fetching the database and converting it into a list. We also declare two regular expressions for accepting only valid IP addresses or IP addresses in CIDR notation. Note that we use the `requests` package for fetching the database.

```python
IP_RE      = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")

def fetch_db(url):
    with requests.get(url) as r:
      ips = [ipaddress.ip_network(l) if '/' in l else ipaddress.ip_address(l) \
          for l in r.text.splitlines() if IP_RE.match(l) or IP_CIDR_RE.match(l)]
    return ips
```

We call into the `fetch_db` function during filament initialization and store the result into the global `__fishy_ips__` list. Additionally, we'll schedule the syncing of the IP database every hour to get the latest definitions of spam nets and attacker IP addresses. Since we're only interested in network events, we'll set the filter accordingly.

```python
IP_DB_URL = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'

def on_init():
    __fishy_ips__ = fetch_db(IP_DB_URL)
    interval(3600)
    kfilter("kevt.category = 'net'")
    columns(["Source", "Destination", "Process"])

def on_interval():
    __fishy_ips__ = fetch_db(IP_DB_URL)
```

Now, we'll implement the main logic for checking whether the network flow is involved in compromised communication such as C&C server requests. Here we simply add a new row and render a table with the source/destination IP address and the process that initiated the network request.

```python
@dotdictify
def on_next_kevent(kevent):
    sip = kevent.kparams.sip
    dip = kevent.kparams.dip
    if (sip in __fishy_ips__ or dip in __fishy_ips__) or \
        (sip or dip in net for net in __fishy_ips__ if isinstance(net, ipaddress.IPv4Network)):
        add_row([sip, dip, kevent.exe])
    render_table()
```

We could have generated an alert and send it via Slack or email. We'll touch on emitting the alerts in [filament alerting](/alerts/filaments).

The full source code of our filament would look similar to the snippet above.

```python
"""
Pinpoints network communications with botnets or C&C servers.
"""

import requests
import re
import ipaddress
from utils.dotdict import dotdictify

IP_RE      = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d|(?:\.\d))")
IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
IP_DB_URL = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'


def fetch_db(url):
    with requests.get(url) as r:
      ips = [ipaddress.ip_network(l) if '/' in l else ipaddress.ip_address(l) \
            for l in r.text.splitlines() if IP_RE.match(l) or IP_CIDR_RE.match(l)]
    return ips


def on_init():
    __fishy_ips__ = fetch_db(IP_DB_URL)
    interval(3600)
    kfilter("kevt.category = 'net'")
    columns(["Source", "Destination", "Process"])


@dotdictify
def on_next_kevent(kevent):
    sip = kevent.kparams.sip
    dip = kevent.kparams.dip
    if (sip in __fishy_ips__ or dip in __fishy_ips__) or \
        (sip or dip in net for net in __fishy_ips__ if isinstance(net, ipaddress.IPv4Network)):
        add_row([sip, dip, kevent.exe])
    render_table()


def on_interval():
    __fishy_ips__ = fetch_db(IP_DB_URL)
```

Save it to, let's say, `cc.py` file inside the `%PROGRAMFILES%\Fibratus\Filaments` directory and you're ready to go. Run the filament with the following command:

```
$ fibratus run -f cc
```
