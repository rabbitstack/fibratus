# Network events

Interprocess communication via TCP/UDP sockets produces all sorts of network events including, sending and receiving data, retransmitting TCP segments or connecting to sockets.

#### Connect

Establishes a connection to the stream-oriented socket. `Connect` events have the following parameters:

- `dip` represents the destination IPv4/IPv6 address of the communication endpoint.
- `sip` represents the source IPv4/IPv6 address of the local process.
- `dport` identifies the destination port.
- `sport` identifies the source port.
- `l4_proto` denotes the type of the Layer 4 protocol. Possible values are `tcp`, `udp`.
- `dport_name` represents the destination port name per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service mappings.
- `sport_name` represents the source port name per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service mappings.

The remaining network events share the same parameters as the `Connect` event.

#### Accept

Accepts the connection request from the socket queue.

#### Send

Sends data over the wire. The kernel generates `Send` events when a process transports data to local or remote endpoint.

#### Recv

Receives data from the socket. The kernel produces `Recv` events when a process is ready to consume data sent by local or remote socket.

#### Disconnect

Terminates data reception on the socket.


#### Reconnect

Reconnects to the socket.

#### Retransmit

Retransmits unacknowledged TCP segments. The kernel networking stack generates retransmissions when packets are dropped due to network congestion, packets arriving out of order and other reasons. 

### DNS queries/responses

DNS telemetry uncovers all DNS query/reply interactions. More specifically, `QueryDns` and `ReplyDns` events are fired when the process sends a query to the name server and when it receives the response from the DNS server, respectively. DNS events are collected by default, but it is possible to disable them by setting the `kstream.enable-dns` config flag to `false`.

#### QueryDns

Sends a query to the name server. This event has the following parameters:

- `name` represents the DNS query (e.g. `www.iana.org`)
- `options` represents the DNS options. It can be the combination of the following values: `STANDARD`, `ACCEPT_TRUNCATED_RESPONSE`, `USE_TCP_ONLY`, `NO_RECURSION`, `BYPASS_CACHE`, `NO_WIRE_QUERY`, `NO_LOCAL_NAME`, `NO_NETBT`, 
`WIRE_ONLY`, `RETURN_MESSAGE`, `MULTICAST_ONLY`, `NO_MULTICAST`, `TREAT_AS_FQDN`, `ADDRCONFIG`, `DUAL_ADDR`, `MULTICAST_WAIT`, 
`MULTICAST_VERIFY`, `DONT_RESET_TTL_VALUES`, `DISABLE_IDN_ENCODING`, `APPEND_MULTILABEL`.
- `rr` specifies the type of the resource record. It can be one of `A`,`NS`, `MD`, `MF`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`,`HINFO`, `MINFO`, `MX`, `TEXT`, `RP`, `AFSDB`, `X25`, `ISDN`, `NSAPPTR`, `SIG`, `KEY`, `PX`, `GPOS`,
`AAAA`, `LOC`, `NXT`, `EID`, `NIMLOC`, `SRV`, `ATMA`, `NAPTR`, `KX`, `CERT`, `A6`, `DNAME`, `SINK`, `OPT`, `DS`, `RRSIG`,
`NSEC`, `DNSKEY` `DHCID`, `UINFO`, `UID`, `GID`, `UNSPEC`, `ADDRS`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, `MAILB`, `MAILA`, `ANY`,
`WINS`, `WINSR`.

#### ReplyDns

Receives the response from the DNS server. DNS reply events contain the following parameters:

- `name` represents the DNS query (e.g. `www.iana.org`)
- `answers` contains the response answers (e.g. `151.101.194.132`, `151.101.130.132`)
- `options` represents the DNS options. It can be the combination of the following values: `STANDARD`, `ACCEPT_TRUNCATED_RESPONSE`, `USE_TCP_ONLY`, `NO_RECURSION`, `BYPASS_CACHE`, `NO_WIRE_QUERY`, `NO_LOCAL_NAME`, `NO_NETBT`, 
`WIRE_ONLY`, `RETURN_MESSAGE`, `MULTICAST_ONLY`, `NO_MULTICAST`, `TREAT_AS_FQDN`, `ADDRCONFIG`, `DUAL_ADDR`, `MULTICAST_WAIT`, 
`MULTICAST_VERIFY`, `DONT_RESET_TTL_VALUES`, `DISABLE_IDN_ENCODING`, `APPEND_MULTILABEL`.
- `rr` specifies the type of the resource record. It can be one of `A`,`NS`, `MD`, `MF`, `CNAME`, `SOA`, `MB`, `MG`, `MR`, `NULL`, `WKS`, `PTR`,`HINFO`, `MINFO`, `MX`, `TEXT`, `RP`, `AFSDB`, `X25`, `ISDN`, `NSAPPTR`, `SIG`, `KEY`, `PX`, `GPOS`,
`AAAA`, `LOC`, `NXT`, `EID`, `NIMLOC`, `SRV`, `ATMA`, `NAPTR`, `KX`, `CERT`, `A6`, `DNAME`, `SINK`, `OPT`, `DS`, `RRSIG`,
`NSEC`, `DNSKEY` `DHCID`, `UINFO`, `UID`, `GID`, `UNSPEC`, `ADDRS`, `TKEY`, `TSIG`, `IXFR`, `AXFR`, `MAILB`, `MAILA`, `ANY`,
`WINS`, `WINSR`.
- `rcode` designates the DNS response code. It can be one of `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`,
`YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE`, `BADSIG`, `BADKEY`, `BADTIME`, `BADNAME`, `INVALID`, `NXDOMAIN`.

### DNS reverse lookups

Fibratus can perform reverse DNS lookups on IP addresses and return a list of domain names that correspond to a particular IP address.

For example, `47.224.186.35.bc.googleusercontent.com` is the reverse lookup representation of the Google IP address.

You can use domain names in [filters](filters/introduction) in conjunction with the `matches`, `contains` or `in` operators. For example, the following filter would match all events that have at least one domain ending with `.domain.`

```
net.sip.names matches ('*.domain.')
```
