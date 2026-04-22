# Network Events

##### Interprocess communication via TCP/UDP sockets produces all sorts of network events including, sending and receiving data, retransmitting TCP segments or connecting to sockets. DNS events are also classified as a subset of network events.

### TCP/UDP events

Fibratus captures TCP and UDP network events at a low level, providing detailed visibility into how processes communicate over the network. By leveraging Windows kernel telemetry, it records connection attempts, accepted connections, data transfers, and endpoint metadata such as IP addresses and ports, all correlated back to the originating process. The following network signals are surfaced:

- `Connect` establishes a connection to the stream-oriented socket.
- `Accept` accepts the connection request from the socket queue.
- `Send` transports data to local or remote endpoint.
- `Recv` consumes data sent by local or remote socket.
- `Disconnect` terminates data reception on the socket.
- `Reconnect` reconnects to the socket.
- `Retransmit` retransmits unacknowledged TCP segments.

All TPC/UDP network events share the same parameter set:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `dip` | Destination IPv4/IPv6 address of the communication endpoint. |
| `sip` | Source IPv4/IPv6 address of the local process. |
| `dport` | Destination port. |
|`sport` | Source port. |
| `l4_proto` | Type of the Layer 4 protocol. Possible values are `tcp`, `udp` |
| `dport_name` | Destination port name per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service mappings. |
| `sport_name` | Source port name per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service mappings. |


### DNS events

DNS telemetry uncovers all DNS query/reply interactions. More specifically, `QueryDns` and `ReplyDns` events are fired when the process sends a query to the name server and when it receives the response from the DNS server, respectively. DNS events are collected by default, but it is possible to disable them by setting the `eventsource.enable-dns` config flag to `false`.

`QueryDns` event is generated when a query is sent to the name server. This event has the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `name` | DNS query, for example, `www.iana.org` |
| `options` | DNS query options. It can be the combination of the following values: `STANDARD`, `ACCEPT_TRUNCATED_RESPONSE`, `USE_TCP_ONLY`, `NO_RECURSION`, `BYPASS_CACHE`, `NO_WIRE_QUERY`, `NO_LOCAL_NAME`, `NO_NETBT`, `WIRE_ONLY`, `RETURN_MESSAGE`, `MULTICAST_ONLY`, `NO_MULTICAST`, `TREAT_AS_FQDN`, `ADDRCONFIG`, `DUAL_ADDR`, `MULTICAST_WAIT`, `MULTICAST_VERIFY`, `DONT_RESET_TTL_VALUES`, `DISABLE_IDN_ENCODING`, `APPEND_MULTILABEL` |
| `rr` | Type of the resource record. It can be one of `A`,`NS`, `MD`, `MF`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`,`HINFO`, `MINFO`, `MX`, `TEXT`, `RP`, `AFSDB`, `X25`, `ISDN`, `NSAPPTR`, `SIG`, `KEY`, `PX`, `GPOS`,`AAAA`, `LOC`, `NXT`, `EID`, `NIMLOC`, `SRV`, `ATMA`, `NAPTR`, `KX`, `CERT`, `A6`, `DNAME`, `SINK`, `OPT`, `DS`, `RRSIG`,`NSEC`, `DNSKEY` `DHCID`, `UINFO`, `UID`, `GID`, `UNSPEC`, `ADDRS`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, `MAILB`, `MAILA`, `ANY`, `WINS`, `WINSR` |


`ReplyDns` event is captured when the the response is received by the DNS server. DNS reply events contain the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `name` | DNS query linked to the response, for example, `www.iana.org` |
| `answers` | Response answers, for example,  `151.101.194.132`
| `options` | DNS response options. It can be the combination of the following values: `STANDARD`, `ACCEPT_TRUNCATED_RESPONSE`, `USE_TCP_ONLY`, `NO_RECURSION`, `BYPASS_CACHE`, `NO_WIRE_QUERY`, `NO_LOCAL_NAME`, `NO_NETBT`, `WIRE_ONLY`, `RETURN_MESSAGE`, `MULTICAST_ONLY`, `NO_MULTICAST`, `TREAT_AS_FQDN`, `ADDRCONFIG`, `DUAL_ADDR`, `MULTICAST_WAIT`, `MULTICAST_VERIFY`, `DONT_RESET_TTL_VALUES`, `DISABLE_IDN_ENCODING`, `APPEND_MULTILABEL`.
| `rr` | Type of the resource record. It can be one of `A`,`NS`, `MD`, `MF`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`,`HINFO`, `MINFO`, `MX`, `TEXT`, `RP`, `AFSDB`, `X25`, `ISDN`, `NSAPPTR`, `SIG`, `KEY`, `PX`, `GPOS`,`AAAA`, `LOC`, `NXT`, `EID`, `NIMLOC`, `SRV`, `ATMA`, `NAPTR`, `KX`, `CERT`, `A6`, `DNAME`, `SINK`, `OPT`, `DS`, `RRSIG`, `NSEC`, `DNSKEY` `DHCID`, `UINFO`, `UID`, `GID`, `UNSPEC`, `ADDRS`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, `MAILB`, `MAILA`, `ANY`, `WINS`, `WINSR` |
| `rcode` | DNS response code. It can be one of `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`,`YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE`, `BADSIG`, `BADKEY`, `BADTIME`, `BADNAME`, `INVALID`, `NXDOMAIN` |

### DNS reverse lookups

Fibratus supports reverse DNS resolution for IP addresses, enabling the retrieval of domain names associated with a given network endpoint. For instance, `47.224.186.35.bc.googleusercontent.com` represents the reverse DNS entry for a Google-owned IP address.

Resolved domain names can be incorporated into detection rules via [filter fields](../../rules/fields.md) to enhance network event analysis.
