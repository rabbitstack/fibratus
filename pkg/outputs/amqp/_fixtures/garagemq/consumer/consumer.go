package consumer

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/interfaces"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/qos"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/queue"
	"sync"
	"sync/atomic"
	"time"
)

const (
	started = iota
	stopped
	paused
)

var cid uint64

// Consumer implements AMQP consumer
type Consumer struct {
	ID          uint64
	Queue       string
	ConsumerTag string
	noAck       bool
	channel     interfaces.Channel
	queue       *queue.Queue
	statusLock  sync.RWMutex
	status      int
	qos         []*qos.AmqpQos
	consume     chan struct{}
}

// NewConsumer returns new instance of Consumer
func NewConsumer(queueName string, consumerTag string, noAck bool, channel interfaces.Channel, queue *queue.Queue, qos []*qos.AmqpQos) *Consumer {
	id := atomic.AddUint64(&cid, 1)
	if consumerTag == "" {
		consumerTag = generateTag(id)
	}
	return &Consumer{
		ID:          id,
		Queue:       queueName,
		ConsumerTag: consumerTag,
		noAck:       noAck,
		channel:     channel,
		queue:       queue,
		qos:         qos,
		consume:     make(chan struct{}, 1),
	}
}

func generateTag(id uint64) string {
	return fmt.Sprintf("%d_%d", time.Now().Unix(), id)
}

// Start starting consumer to fetch messages from queue
func (consumer *Consumer) Start() {
	consumer.status = started
	go consumer.startConsume()
	consumer.Consume()
}

// startConsume waiting a signal from consume channel and try to pop message from queue
// if not set noAck consumer pop message with qos rules and add message to unacked message queue
func (consumer *Consumer) startConsume() {
	for range consumer.consume {
		consumer.retrieveAndSendMessage()
	}
}

func (consumer *Consumer) retrieveAndSendMessage() {
	var message *amqp.Message
	consumer.statusLock.RLock()
	defer consumer.statusLock.RUnlock()
	if consumer.status == stopped {
		return
	}

	if consumer.noAck {
		message = consumer.queue.Pop()
	} else {
		message = consumer.queue.PopQos(consumer.qos)
	}

	if message == nil {
		return
	}

	dTag := consumer.channel.NextDeliveryTag()
	if !consumer.noAck {
		consumer.channel.AddUnackedMessage(dTag, consumer.ConsumerTag, consumer.queue.GetName(), message)
	}

	consumer.channel.SendContent(&amqp.BasicDeliver{
		ConsumerTag: consumer.ConsumerTag,
		DeliveryTag: dTag,
		Redelivered: message.DeliveryCount > 1,
		Exchange:    message.Exchange,
		RoutingKey:  message.RoutingKey,
	}, message)

	consumer.consumeMsg()

	return
}

// Pause pause consumer, used by channel.flow change
func (consumer *Consumer) Pause() {
	consumer.statusLock.Lock()
	defer consumer.statusLock.Unlock()
	consumer.status = paused
}

// UnPause unpause consumer, used by channel.flow change
func (consumer *Consumer) UnPause() {
	consumer.statusLock.Lock()
	defer consumer.statusLock.Unlock()
	consumer.status = started
}

// Consume send signal into consumer channel, than consumer can try to pop message from queue
func (consumer *Consumer) Consume() bool {
	consumer.statusLock.RLock()
	defer consumer.statusLock.RUnlock()

	return consumer.consumeMsg()
}

func (consumer *Consumer) consumeMsg() bool {
	if consumer.status == stopped || consumer.status == paused {
		return false
	}

	select {
	case consumer.consume <- struct{}{}:
		return true
	default:
		return false
	}
}

// Stop stops consumer and remove it from queue consumers list
func (consumer *Consumer) Stop() {
	consumer.statusLock.Lock()
	if consumer.status == stopped {
		consumer.statusLock.Unlock()
		return
	}
	consumer.status = stopped
	consumer.statusLock.Unlock()
	consumer.queue.RemoveConsumer(consumer.ConsumerTag)
	close(consumer.consume)
}

// Cancel stops consumer and send basic.cancel method to the client
func (consumer *Consumer) Cancel() {
	consumer.Stop()
	consumer.channel.SendMethod(&amqp.BasicCancel{ConsumerTag: consumer.ConsumerTag, NoWait: true})
}

// Tag returns consumer tag
func (consumer *Consumer) Tag() string {
	return consumer.ConsumerTag
}

// Qos returns consumer qos rules
func (consumer *Consumer) Qos() []*qos.AmqpQos {
	return consumer.qos
}
