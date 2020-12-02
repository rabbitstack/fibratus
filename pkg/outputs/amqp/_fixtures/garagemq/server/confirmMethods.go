package server

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
)

func (channel *Channel) confirmRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.ConfirmSelect:
		return channel.confirmSelect(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route channel method "+method.Name(), method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) confirmSelect(method *amqp.ConfirmSelect) (err *amqp.Error) {
	channel.confirmMode = true
	go channel.sendConfirms()
	if !method.Nowait {
		channel.SendMethod(&amqp.ConfirmSelectOk{})
	}
	return nil
}
