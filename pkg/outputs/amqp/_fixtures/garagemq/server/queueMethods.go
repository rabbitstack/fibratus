package server

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/binding"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/exchange"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/queue"
)

func (channel *Channel) queueRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.QueueDeclare:
		return channel.queueDeclare(method)
	case *amqp.QueueBind:
		return channel.queueBind(method)
	case *amqp.QueueUnbind:
		return channel.queueUnbind(method)
	case *amqp.QueuePurge:
		return channel.queuePurge(method)
	case *amqp.QueueDelete:
		return channel.queueDelete(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route queue method "+method.Name(), method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) queueDeclare(method *amqp.QueueDeclare) *amqp.Error {
	var existingQueue *queue.Queue
	var notFoundErr, exclusiveErr *amqp.Error

	if method.Queue == "" {
		return amqp.NewChannelError(
			amqp.CommandInvalid,
			"queue name is required",
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	existingQueue, notFoundErr = channel.getQueueWithError(method.Queue, method)
	exclusiveErr = channel.checkQueueLockWithError(existingQueue, method)

	if method.Passive {
		if method.NoWait {
			return nil
		}

		if existingQueue == nil {
			return notFoundErr
		}

		if exclusiveErr != nil {
			return exclusiveErr
		}

		channel.SendMethod(&amqp.QueueDeclareOk{
			Queue:         method.Queue,
			MessageCount:  uint32(existingQueue.Length()),
			ConsumerCount: uint32(existingQueue.ConsumersCount()),
		})

		return nil
	}

	newQueue := channel.conn.GetVirtualHost().NewQueue(
		method.Queue,
		channel.conn.id,
		method.Exclusive,
		method.AutoDelete,
		method.Durable,
		channel.server.config.Queue.ShardSize,
	)

	if existingQueue != nil {
		if exclusiveErr != nil {
			return exclusiveErr
		}

		if err := existingQueue.EqualWithErr(newQueue); err != nil {
			return amqp.NewChannelError(
				amqp.PreconditionFailed,
				err.Error(),
				method.ClassIdentifier(),
				method.MethodIdentifier(),
			)
		}

		channel.SendMethod(&amqp.QueueDeclareOk{
			Queue:         method.Queue,
			MessageCount:  uint32(existingQueue.Length()),
			ConsumerCount: uint32(existingQueue.ConsumersCount()),
		})
		return nil
	}

	newQueue.Start()
	err := channel.conn.GetVirtualHost().AppendQueue(newQueue)
	if err != nil {
		return amqp.NewChannelError(
			amqp.PreconditionFailed,
			err.Error(),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}
	channel.SendMethod(&amqp.QueueDeclareOk{
		Queue:         method.Queue,
		MessageCount:  0,
		ConsumerCount: 0,
	})

	return nil
}

func (channel *Channel) queueBind(method *amqp.QueueBind) *amqp.Error {
	var ex *exchange.Exchange
	var qu *queue.Queue
	var err *amqp.Error

	if ex, err = channel.getExchangeWithError(method.Exchange, method); err != nil {
		return err
	}

	// @spec-note
	// The server MUST NOT allow clients to access the default exchange except by specifying an empty exchange name in the Queue.Bind and content Publish methods.
	if ex.GetName() == exDefaultName {
		return amqp.NewChannelError(
			amqp.AccessRefused,
			fmt.Sprintf("operation not permitted on the default exchange"),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return err
	}

	if err = channel.checkQueueLockWithError(qu, method); err != nil {
		return err
	}

	bind, bindErr := binding.NewBinding(method.Queue, method.Exchange,
		method.RoutingKey, method.Arguments, ex.ExType() == exchange.ExTypeTopic)
	if bindErr != nil {
		return amqp.NewChannelError(
			amqp.PreconditionFailed,
			bindErr.Error(),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)

	}

	ex.AppendBinding(bind)

	// @spec-note
	// Bindings of durable queues to durable exchanges are automatically durable and the server MUST restore such bindings after a server restart.
	if ex.IsDurable() && qu.IsDurable() {
		channel.conn.GetVirtualHost().PersistBinding(bind)
	}

	if !method.NoWait {
		channel.SendMethod(&amqp.QueueBindOk{})
	}

	return nil
}

func (channel *Channel) queueUnbind(method *amqp.QueueUnbind) *amqp.Error {
	var ex *exchange.Exchange
	var qu *queue.Queue
	var err *amqp.Error

	if ex, err = channel.getExchangeWithError(method.Exchange, method); err != nil {
		return err
	}

	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return err
	}

	if err = channel.checkQueueLockWithError(qu, method); err != nil {
		return err
	}

	bind, bindErr := binding.NewBinding(method.Queue, method.Exchange, method.RoutingKey, method.Arguments, ex.ExType() == exchange.ExTypeTopic)

	if bindErr != nil {
		return amqp.NewConnectionError(
			amqp.PreconditionFailed,
			bindErr.Error(),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	ex.RemoveBinding(bind)
	channel.conn.GetVirtualHost().RemoveBindings([]*binding.Binding{bind})
	channel.SendMethod(&amqp.QueueUnbindOk{})

	return nil
}

func (channel *Channel) queuePurge(method *amqp.QueuePurge) *amqp.Error {
	var qu *queue.Queue
	var err *amqp.Error

	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return err
	}

	if err = channel.checkQueueLockWithError(qu, method); err != nil {
		return err
	}

	msgCnt := qu.Purge()
	if !method.NoWait {
		channel.SendMethod(&amqp.QueuePurgeOk{MessageCount: uint32(msgCnt)})
	}
	return nil
}

func (channel *Channel) queueDelete(method *amqp.QueueDelete) *amqp.Error {
	var qu *queue.Queue
	var err *amqp.Error

	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return err
	}

	if err = channel.checkQueueLockWithError(qu, method); err != nil {
		return err
	}

	var length, errDel = channel.conn.GetVirtualHost().DeleteQueue(method.Queue, method.IfUnused, method.IfEmpty)
	if errDel != nil {
		return amqp.NewChannelError(amqp.PreconditionFailed, errDel.Error(), method.ClassIdentifier(), method.MethodIdentifier())
	}

	channel.SendMethod(&amqp.QueueDeleteOk{MessageCount: uint32(length)})
	return nil
}
