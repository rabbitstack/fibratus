# RabbitMQ

The RabbitMQ output sends events to the [RabbitMQ](https://www.rabbitmq.com/) message broker. Various events are buffered and sent as part of a single AMQP message.

### Configuration {docsify-ignore}

The RabbitMQ output configuration is located in the `outputs.amqp` section.

#### enabled

Specifies whether the RabbitMQ output sink is enabled.

**default**: `false`

#### url

Represents the AMQP connection string.

**default**: `amqp://localhost:5672`

#### timeout

Specifies the AMQP connection timeout.

**default**: `5s`

#### exchange

Specifies the target AMQP exchange name that receives inbound event message flow.

**default**: `fibratus`

#### exchange-type

Represents  the AMQP exchange type. Available exchange type include common types are `direct`, `fanout`,
`topic`, `header`, and `x-consistent-hash`. To learn more about exchange types, refer to the RabbitMQ [docs](https://www.rabbitmq.com/tutorials/amqp-concepts.html#exchanges).

#### routing-key

Represents the static routing key to link exchanges with queues.

**default**: `fibratus`

#### vhost

Represents the AMQP virtual host name.

**default**: `/`

#### durable

Indicates if the exchange is marked as durable. Durable exchanges can survive broker restarts.

**default**: `false`

#### passive

Indicates if the server checks whether the exchange already exists and raises an error if it doesn't exist.

**default**: `false`

#### delivery-mode

Determines if a published message is persistent or transient.

**default**: `transient`

#### username

The username for the plain authentication method.

#### password

The password for the plain authentication method.

#### headers

Designates a collection of static headers that are added to each published message.

#### tls-key

Path to the public/private key file.

#### tls-cert

Path to the certificate file.

#### tls-ca

Represents the path of the certificate file that is associated with the Certification Authority (CA).

#### tls-insecure-skip-verify

Indicates if the chain and host verification stage is skipped.

**default**: `false`
