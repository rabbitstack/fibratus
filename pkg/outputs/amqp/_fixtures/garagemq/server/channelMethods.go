package server

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
)

func (channel *Channel) channelRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.ChannelOpen:
		return channel.channelOpen(method)
	case *amqp.ChannelClose:
		return channel.channelClose(method)
	case *amqp.ChannelCloseOk:
		return channel.channelCloseOk(method)
	case *amqp.ChannelFlow:
		return channel.channelFlow(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route channel method "+method.Name(), method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) channelOpen(method *amqp.ChannelOpen) (err *amqp.Error) {
	// @spec-note
	// The client MUST NOT use this method on an already­opened channel.
	if channel.status == channelOpen {
		return amqp.NewConnectionError(amqp.ChannelError, "channel already open", method.ClassIdentifier(), method.MethodIdentifier())
	}

	channel.SendMethod(&amqp.ChannelOpenOk{})
	channel.status = channelOpen

	return nil
}

func (channel *Channel) channelClose(method *amqp.ChannelClose) (err *amqp.Error) {
	channel.status = channelClosed
	channel.SendMethod(&amqp.ChannelCloseOk{})
	channel.close()
	return nil
}

func (channel *Channel) channelCloseOk(method *amqp.ChannelCloseOk) (err *amqp.Error) {
	channel.status = channelClosed
	return nil
}

func (channel *Channel) channelFlow(method *amqp.ChannelFlow) (err *amqp.Error) {
	channel.changeFlow(method.Active)
	channel.SendMethod(&amqp.ChannelFlowOk{Active: method.Active})
	return nil
}
