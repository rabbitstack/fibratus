# RabbitMQ

##### The RabbitMQ output transmits events to the [RabbitMQ](https://www.rabbitmq.com/) messaging system. Events are buffered and published in batches as a single AMQP message to improve transmission efficiency and reduce overhead.


## Configuration 

The RabbitMQ output configuration is located in the `outputs.amqp` section.

### `enabled`

Specifies whether the RabbitMQ output sink is enabled.


### `url`

Represents the AMQP connection string.


### `timeout`

Specifies the AMQP connection timeout.


### `exchange`

Specifies the target AMQP exchange name that receives inbound event message flow.


### `exchange-type`

Represents  the AMQP exchange type. Available exchange type include common types are `direct`, `fanout`,
`topic`, `header`, and `x-consistent-hash`. To learn more about exchange types, refer to the RabbitMQ [docs](https://www.rabbitmq.com/tutorials/amqp-concepts.html#exchanges).

### `routing-key`

Represents the static routing key to link exchanges with queues.

### `vhost`

Represents the AMQP virtual host name.

### `durable`

Indicates if the exchange is marked as durable. Durable exchanges can survive broker restarts.


### `passive`

Indicates if the server checks whether the exchange already exists and raises an error if it doesn't exist.


### `delivery-mode`

Determines if a published message is persistent or transient.

### `username`

The username for the plain authentication method.

### `password`

The password for the plain authentication method.

### `headers`

Designates a collection of static headers that are added to each published message.

### `tls-key`

Path to the public/private key file.

### `tls-cert`

Path to the certificate file.

### `tls-ca`

Represents the path of the certificate file that is associated with the Certification Authority (CA).

### `tls-insecure-skip-verify`

Indicates if the chain and host verification stage is skipped.
