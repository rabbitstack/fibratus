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

Receives data from the socket. The kernel produces `Recv` events a process is ready to consume data sent by local or remote socket.

#### Disconnect

Terminates data reception on the socket.


#### Reconnect

Reconnects to the socket.

#### Retransmit

Retransmits unacknowledged TCP segments. The kernel networking stack generates retransmissions when packets are dropped due to network congestion, packets arriving out of order and other reasons. 
