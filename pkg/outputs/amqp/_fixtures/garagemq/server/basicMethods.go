package server

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/consumer"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/qos"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/queue"
)

func (channel *Channel) basicRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.BasicQos:
		return channel.basicQos(method)
	case *amqp.BasicPublish:
		return channel.basicPublish(method)
	case *amqp.BasicConsume:
		return channel.basicConsume(method)
	case *amqp.BasicAck:
		return channel.basicAck(method)
	case *amqp.BasicNack:
		return channel.basicNack(method)
	case *amqp.BasicReject:
		return channel.basicReject(method)
	case *amqp.BasicCancel:
		return channel.basicCancel(method)
	case *amqp.BasicGet:
		return channel.basicGet(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route basic method "+method.Name(), method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) basicQos(method *amqp.BasicQos) (err *amqp.Error) {
	channel.updateQos(method.PrefetchCount, method.PrefetchSize, method.Global)
	channel.SendMethod(&amqp.BasicQosOk{})

	return nil
}

func (channel *Channel) basicAck(method *amqp.BasicAck) (err *amqp.Error) {
	return channel.handleAck(method)
}

func (channel *Channel) basicNack(method *amqp.BasicNack) (err *amqp.Error) {
	return channel.handleReject(method.DeliveryTag, method.Multiple, method.Requeue, method)
}

func (channel *Channel) basicReject(method *amqp.BasicReject) (err *amqp.Error) {
	return channel.handleReject(method.DeliveryTag, false, method.Requeue, method)
}

func (channel *Channel) basicPublish(method *amqp.BasicPublish) (err *amqp.Error) {
	if method.Immediate {
		return amqp.NewChannelError(amqp.NotImplemented, "Immediate = true", method.ClassIdentifier(), method.MethodIdentifier())
	}

	if _, err = channel.getExchangeWithError(method.Exchange, method); err != nil {
		return err
	}

	channel.currentMessage = amqp.NewMessage(method)
	if channel.confirmMode {
		channel.currentMessage.ConfirmMeta = &amqp.ConfirmMeta{
			ChanID:      channel.id,
			ConnID:      channel.conn.id,
			DeliveryTag: channel.nextConfirmDeliveryTag(),
		}
	}
	return nil
}

func (channel *Channel) basicConsume(method *amqp.BasicConsume) (err *amqp.Error) {
	var cmr *consumer.Consumer
	if cmr, err = channel.addConsumer(method); err != nil {
		return err
	}

	if !method.NoWait {
		channel.SendMethod(&amqp.BasicConsumeOk{ConsumerTag: cmr.Tag()})
	}

	cmr.Start()

	return nil
}

func (channel *Channel) basicCancel(method *amqp.BasicCancel) (err *amqp.Error) {
	if _, ok := channel.consumers[method.ConsumerTag]; !ok {
		return amqp.NewChannelError(amqp.NotFound, "Consumer not found", method.ClassIdentifier(), method.MethodIdentifier())
	}
	channel.removeConsumer(method.ConsumerTag)
	channel.SendMethod(&amqp.BasicCancelOk{ConsumerTag: method.ConsumerTag})
	return nil
}

func (channel *Channel) basicGet(method *amqp.BasicGet) (err *amqp.Error) {
	var qu *queue.Queue
	var message *amqp.Message
	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return err
	}

	if method.NoAck {
		message = qu.Pop()
	} else {
		message = qu.PopQos([]*qos.AmqpQos{channel.qos, channel.conn.qos})
	}

	// how to handle if queue is not empty, but qos triggered and message is nil
	if message == nil {
		channel.SendMethod(&amqp.BasicGetEmpty{})
		return nil
	}

	dTag := channel.NextDeliveryTag()
	if !method.NoAck {
		channel.AddUnackedMessage(dTag, "", qu.GetName(), message)
	} else {
	}

	channel.SendContent(&amqp.BasicGetOk{
		DeliveryTag:  dTag,
		Redelivered:  false,
		Exchange:     message.Exchange,
		RoutingKey:   message.RoutingKey,
		MessageCount: 1,
	}, message)

	return nil
}
