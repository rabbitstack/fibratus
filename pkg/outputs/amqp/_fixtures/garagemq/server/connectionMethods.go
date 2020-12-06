package server

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/auth"
	"os"
	"runtime"
)

func (channel *Channel) connectionRoute(method amqp.Method) *amqp.Error {
	switch method := method.(type) {
	case *amqp.ConnectionStartOk:
		return channel.connectionStartOk(method)
	case *amqp.ConnectionTuneOk:
		return channel.connectionTuneOk(method)
	case *amqp.ConnectionOpen:
		return channel.connectionOpen(method)
	case *amqp.ConnectionClose:
		return channel.connectionClose(method)
	case *amqp.ConnectionCloseOk:
		return channel.connectionCloseOk(method)
	}

	return amqp.NewConnectionError(amqp.NotImplemented, "unable to route connection method", method.ClassIdentifier(), method.MethodIdentifier())
}

func (channel *Channel) connectionStart() {
	var capabilities = amqp.Table{}
	capabilities["publisher_confirms"] = true
	capabilities["exchange_exchange_bindings"] = false
	capabilities["basic.nack"] = true
	capabilities["consumer_cancel_notify"] = true
	capabilities["connection.blocked"] = false
	capabilities["consumer_priorities"] = false
	capabilities["authentication_failure_close"] = true
	capabilities["per_consumer_qos"] = true

	var serverProps = amqp.Table{}
	serverProps["product"] = "garagemq"
	serverProps["version"] = "0.1"
	serverProps["copyright"] = "Alexander Valinurov, 2018"
	serverProps["platform"] = runtime.GOARCH
	serverProps["capabilities"] = capabilities
	host, err := os.Hostname()
	if err != nil {
		serverProps["host"] = "UnknownHostError"
	} else {
		serverProps["host"] = host
	}

	var method = amqp.ConnectionStart{VersionMajor: 0, VersionMinor: 9, ServerProperties: &serverProps, Mechanisms: []byte("PLAIN"), Locales: []byte("en_US")}
	channel.SendMethod(&method)

	channel.conn.statusLock.Lock()
	defer channel.conn.statusLock.Unlock()
	channel.conn.status = ConnStart
}

func (channel *Channel) connectionStartOk(method *amqp.ConnectionStartOk) *amqp.Error {
	channel.conn.status = ConnStartOK

	var saslData auth.SaslData
	var err error
	if saslData, err = auth.ParsePlain(method.Response); err != nil {
		return amqp.NewConnectionError(amqp.NotAllowed, "login failure", method.ClassIdentifier(), method.MethodIdentifier())
	}

	if method.Mechanism != auth.SaslPlain {
		channel.conn.close()
	}

	if !channel.server.checkAuth(saslData) {
		return amqp.NewConnectionError(amqp.NotAllowed, "login failure", method.ClassIdentifier(), method.MethodIdentifier())
	}
	channel.conn.userName = saslData.Username
	channel.conn.clientProperties = method.ClientProperties

	// @todo Send HeartBeat 0 cause not supported yet
	channel.SendMethod(&amqp.ConnectionTune{
		ChannelMax: channel.conn.maxChannels,
		FrameMax:   channel.conn.maxFrameSize,
		Heartbeat:  channel.conn.heartbeatInterval,
	})
	channel.conn.statusLock.Lock()
	defer channel.conn.statusLock.Unlock()
	channel.conn.status = ConnTune

	return nil
}

func (channel *Channel) connectionTuneOk(method *amqp.ConnectionTuneOk) *amqp.Error {
	channel.conn.statusLock.Lock()
	defer channel.conn.statusLock.Unlock()
	channel.conn.status = ConnTuneOK

	if method.ChannelMax > channel.conn.maxChannels || method.FrameMax > channel.conn.maxFrameSize {
		channel.conn.close()
		return nil
	}

	channel.conn.maxChannels = method.ChannelMax
	channel.conn.maxFrameSize = method.FrameMax

	if method.Heartbeat > 0 {
		if method.Heartbeat < channel.conn.heartbeatInterval {
			channel.conn.heartbeatInterval = method.Heartbeat
		}
		channel.conn.heartbeatTimeout = channel.conn.heartbeatInterval * 3
		go channel.conn.heartBeater()
	}

	return nil
}

func (channel *Channel) connectionOpen(method *amqp.ConnectionOpen) *amqp.Error {
	channel.conn.status = ConnOpen
	var vhostFound bool
	if channel.conn.virtualHost, vhostFound = channel.server.vhosts[method.VirtualHost]; !vhostFound {
		return amqp.NewConnectionError(amqp.InvalidPath, "virtualHost '"+method.VirtualHost+"' does not exist", method.ClassIdentifier(), method.MethodIdentifier())
	}

	channel.conn.vhostName = method.VirtualHost

	channel.SendMethod(&amqp.ConnectionOpenOk{})
	channel.conn.statusLock.Lock()
	defer channel.conn.statusLock.Unlock()
	channel.conn.status = ConnOpenOK

	channel.logger.Info("AMQP connection open")
	return nil
}

func (channel *Channel) connectionClose(method *amqp.ConnectionClose) *amqp.Error {
	channel.logger.Infof("Connection closed by client, reason - [%d] %s", method.ReplyCode, method.ReplyText)
	channel.SendMethod(&amqp.ConnectionCloseOk{})
	return nil
}

func (channel *Channel) connectionCloseOk(method *amqp.ConnectionCloseOk) *amqp.Error {
	go channel.conn.close()
	return nil
}
