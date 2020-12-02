package server

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/exchange"
	"strings"
)

func (channel *Channel) exchangeRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.ExchangeDeclare:
		return channel.exchangeDeclare(method)
	case *amqp.ExchangeDelete:
		return channel.exchangeDelete(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route queue method "+method.Name(), method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) exchangeDeclare(method *amqp.ExchangeDeclare) *amqp.Error {
	exTypeId, err := exchange.GetExchangeTypeID(method.Type)
	if err != nil {
		return amqp.NewChannelError(amqp.NotImplemented, err.Error(), method.ClassIdentifier(), method.MethodIdentifier())
	}

	if method.Exchange == "" {
		return amqp.NewChannelError(
			amqp.CommandInvalid,
			"exchange name is required",
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	existingExchange := channel.conn.GetVirtualHost().GetExchange(method.Exchange)
	if method.Passive {
		if method.NoWait {
			return nil
		}

		if existingExchange == nil {
			return amqp.NewChannelError(
				amqp.NotFound,
				fmt.Sprintf("exchange '%s' not found", method.Exchange),
				method.ClassIdentifier(),
				method.MethodIdentifier(),
			)
		}

		channel.SendMethod(&amqp.ExchangeDeclareOk{})

		return nil
	}

	if strings.HasPrefix(method.Exchange, "amq.") {
		return amqp.NewChannelError(
			amqp.AccessRefused,
			fmt.Sprintf("exchange name '%s' contains reserved prefix 'amq.*'", method.Exchange),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	newExchange := exchange.NewExchange(
		method.Exchange,
		exTypeId,
		method.Durable,
		method.AutoDelete,
		method.Internal,
		false,
	)

	if existingExchange != nil {
		if err := existingExchange.EqualWithErr(newExchange); err != nil {
			return amqp.NewChannelError(
				amqp.PreconditionFailed,
				err.Error(),
				method.ClassIdentifier(),
				method.MethodIdentifier(),
			)
		}
		channel.SendMethod(&amqp.ExchangeDeclareOk{})
		return nil
	}

	channel.conn.GetVirtualHost().AppendExchange(newExchange)
	if !method.NoWait {
		channel.SendMethod(&amqp.ExchangeDeclareOk{})
	}

	return nil
}

func (channel *Channel) exchangeDelete(method *amqp.ExchangeDelete) *amqp.Error {
	return nil
}
