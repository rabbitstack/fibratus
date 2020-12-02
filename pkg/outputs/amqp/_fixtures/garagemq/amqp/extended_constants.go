package amqp

// NoRoute returns when a 'mandatory' message cannot be delivered to any queue.
// @see https://www.rabbitmq.com/amqp-0-9-1-errata.html#section_17
const NoRoute = 312
