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
