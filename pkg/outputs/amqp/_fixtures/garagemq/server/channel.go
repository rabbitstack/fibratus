package server

import (
	"bytes"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/consumer"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/exchange"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/pool"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/qos"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/queue"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

const (
	channelNew = iota
	channelOpen
	channelClosing
	channelClosed
	channelDelete
)

// Channel is an implementation of the AMQP-channel entity
// Within a single socket connection, there can be multiple
// independent threads of control, called "channels"
type Channel struct {
	active             bool
	confirmMode        bool
	id                 uint16
	conn               *Connection
	server             *Server
	incoming           chan *amqp.Frame
	outgoing           chan *amqp.Frame
	logger             *log.Entry
	status             int
	protoVersion       string
	currentMessage     *amqp.Message
	cmrLock            sync.RWMutex
	consumers          map[string]*consumer.Consumer
	qos                *qos.AmqpQos
	consumerQos        *qos.AmqpQos
	deliveryTag        uint64
	confirmDeliveryTag uint64
	confirmLock        sync.Mutex
	confirmQueue       []*amqp.ConfirmMeta
	ackLock            sync.Mutex
	ackStore           map[uint64]*UnackedMessage
	statusLock         sync.Mutex

	bufferPool *pool.BufferPool

	closeCh chan bool
}

// UnackedMessage represents the unacknowledged message
type UnackedMessage struct {
	cTag  string
	msg   *amqp.Message
	queue string
}

// NewChannel returns new instance of Channel
func NewChannel(id uint16, conn *Connection) *Channel {
	channel := &Channel{
		active: true,
		id:     id,
		conn:   conn,
		server: conn.server,
		// for incoming channel much capacity is good for performance
		// but it is difficult to implement processing already queued frames on shutdown or connection close
		incoming:     make(chan *amqp.Frame, 128),
		outgoing:     conn.outgoing,
		status:       channelNew,
		protoVersion: conn.server.protoVersion,
		consumers:    make(map[string]*consumer.Consumer),
		qos:          qos.NewAmqpQos(0, 0),
		consumerQos:  qos.NewAmqpQos(0, 0),
		ackStore:     make(map[uint64]*UnackedMessage),
		confirmQueue: make([]*amqp.ConfirmMeta, 0),
		closeCh:      make(chan bool),
		bufferPool:   pool.NewBufferPool(0),
	}

	channel.logger = log.WithFields(log.Fields{
		"connectionId": conn.id,
		"channelId":    id,
	})

	return channel
}

func (channel *Channel) start() {
	if channel.id == 0 {
		go channel.connectionStart()
	}

	go channel.handleIncoming()
}

func (channel *Channel) handleIncoming() {
	buffer := bytes.NewReader([]byte{})

	// TODO
	// @spec-note
	// After sending channel.close, any received methods except Close and Close­OK MUST be discarded.
	// The response to receiving a Close after sending Close must be to send Close­Ok.
	for {
		select {
		case <-channel.closeCh:
			channel.close()
			return
		case frame := <-channel.incoming:
			if frame == nil {
				// channel.incoming closed by connection
				return
			}

			switch frame.Type {
			case amqp.FrameMethod:
				buffer.Reset(frame.Payload)
				method, err := amqp.ReadMethod(buffer, channel.protoVersion)
				channel.logger.Debug("Incoming method <- " + method.Name())
				if err != nil {
					channel.logger.WithError(err).Error("Error on handling frame")
					channel.sendError(amqp.NewConnectionError(amqp.FrameError, err.Error(), 0, 0))
				}

				if err := channel.handleMethod(method); err != nil {
					channel.sendError(err)
				}
			case amqp.FrameHeader:
				if err := channel.handleContentHeader(frame); err != nil {
					channel.sendError(err)
				}
			case amqp.FrameBody:
				if err := channel.handleContentBody(frame); err != nil {
					channel.sendError(err)
				}
			}
		}
	}
}

func (channel *Channel) sendError(err *amqp.Error) {
	channel.logger.Error(err)
	switch err.ErrorType {
	case amqp.ErrorOnChannel:
		channel.status = channelClosing
		channel.SendMethod(&amqp.ChannelClose{
			ReplyCode: err.ReplyCode,
			ReplyText: err.ReplyText,
			ClassID:   err.ClassID,
			MethodID:  err.MethodID,
		})
	case amqp.ErrorOnConnection:
		ch := channel.conn.getChannel(0)
		if ch != nil {
			ch.SendMethod(&amqp.ConnectionClose{
				ReplyCode: err.ReplyCode,
				ReplyText: err.ReplyText,
				ClassID:   err.ClassID,
				MethodID:  err.MethodID,
			})
		}
	}
}

func (channel *Channel) handleMethod(method amqp.Method) *amqp.Error {
	switch method.ClassIdentifier() {
	case amqp.ClassConnection:
		return channel.connectionRoute(method)
	case amqp.ClassChannel:
		return channel.channelRoute(method)
	case amqp.ClassBasic:
		return channel.basicRoute(method)
	case amqp.ClassExchange:
		return channel.exchangeRoute(method)
	case amqp.ClassQueue:
		return channel.queueRoute(method)
	case amqp.ClassConfirm:
		return channel.confirmRoute(method)
	}

	return nil
}

func (channel *Channel) handleContentHeader(headerFrame *amqp.Frame) *amqp.Error {
	reader := bytes.NewReader(headerFrame.Payload)
	var err error
	if channel.currentMessage == nil {
		return amqp.NewConnectionError(amqp.FrameError, "unexpected content header frame", 0, 0)
	}

	if channel.currentMessage.Header != nil {
		return amqp.NewConnectionError(amqp.FrameError, "unexpected content header frame - header already exists", 0, 0)
	}

	if channel.currentMessage.Header, err = amqp.ReadContentHeader(reader, channel.protoVersion); err != nil {
		return amqp.NewConnectionError(amqp.FrameError, "error on parsing content header frame", 0, 0)
	}

	return nil
}

func (channel *Channel) handleContentBody(bodyFrame *amqp.Frame) *amqp.Error {
	if channel.currentMessage == nil {
		return amqp.NewConnectionError(amqp.FrameError, "unexpected content body frame", 0, 0)
	}

	if channel.currentMessage.Header == nil {
		return amqp.NewConnectionError(amqp.FrameError, "unexpected content body frame - no header yet", 0, 0)
	}

	channel.currentMessage.Append(bodyFrame)

	if channel.currentMessage.BodySize < channel.currentMessage.Header.BodySize {
		return nil
	}

	vhost := channel.conn.GetVirtualHost()
	message := channel.currentMessage
	ex := vhost.GetExchange(message.Exchange)
	if ex == nil {
		channel.SendContent(
			&amqp.BasicReturn{ReplyCode: amqp.NoRoute, ReplyText: "No route", Exchange: message.Exchange, RoutingKey: message.RoutingKey},
			message,
		)

		channel.addConfirm(message.ConfirmMeta)

		return nil
	}
	matchedQueues := ex.GetMatchedQueues(message)

	if len(matchedQueues) == 0 {
		if message.Mandatory {
			channel.SendContent(
				&amqp.BasicReturn{ReplyCode: amqp.NoRoute, ReplyText: "No route", Exchange: message.Exchange, RoutingKey: message.RoutingKey},
				message,
			)
		}

		channel.addConfirm(message.ConfirmMeta)

		return nil
	}

	if channel.confirmMode {
		message.ConfirmMeta.ExpectedConfirms = len(matchedQueues)
	}

	for queueName := range matchedQueues {
		qu := channel.conn.GetVirtualHost().GetQueue(queueName)
		if qu == nil {
			if message.Mandatory {
				channel.SendContent(
					&amqp.BasicReturn{ReplyCode: amqp.NoRoute, ReplyText: "No route", Exchange: message.Exchange, RoutingKey: message.RoutingKey},
					message,
				)
			}

			channel.addConfirm(message.ConfirmMeta)

			return nil
		}

		qu.Push(message)

		if channel.confirmMode && message.ConfirmMeta.CanConfirm() && !message.IsPersistent() {
			channel.addConfirm(message.ConfirmMeta)
		}
	}
	return nil
}

// SendMethod send method to client
// Method will be packed into frame and send to outgoing channel
func (channel *Channel) SendMethod(method amqp.Method) {
	var rawMethod = channel.bufferPool.Get()
	if err := amqp.WriteMethod(rawMethod, method, channel.server.protoVersion); err != nil {
		logrus.WithError(err).Error("Error")
	}

	closeAfter := method.ClassIdentifier() == amqp.ClassConnection && method.MethodIdentifier() == amqp.MethodConnectionCloseOk

	channel.logger.Debug("Outgoing -> " + method.Name())

	payload := make([]byte, rawMethod.Len())
	copy(payload, rawMethod.Bytes())
	channel.bufferPool.Put(rawMethod)

	channel.sendOutgoing(&amqp.Frame{Type: byte(amqp.FrameMethod), ChannelID: channel.id, Payload: payload, CloseAfter: closeAfter, Sync: method.Sync()})
}

func (channel *Channel) sendOutgoing(frame *amqp.Frame) {
	select {
	case <-channel.conn.ctx.Done():
		if channel.id == 0 {
			close(channel.outgoing)
		}
	case channel.outgoing <- frame:
	}
}

// SendContent send message to consumers or returns to publishers
func (channel *Channel) SendContent(method amqp.Method, message *amqp.Message) {
	channel.SendMethod(method)

	var rawHeader = channel.bufferPool.Get()
	amqp.WriteContentHeader(rawHeader, message.Header, channel.server.protoVersion)

	payload := make([]byte, rawHeader.Len())
	copy(payload, rawHeader.Bytes())
	channel.bufferPool.Put(rawHeader)

	channel.sendOutgoing(&amqp.Frame{Type: byte(amqp.FrameHeader), ChannelID: channel.id, Payload: payload, CloseAfter: false})

	for _, payload := range message.Body {
		payload.ChannelID = channel.id
		channel.sendOutgoing(payload)
	}

	switch method.(type) {
	case *amqp.BasicDeliver:
	}
}

func (channel *Channel) addConfirm(meta *amqp.ConfirmMeta) {
	if !channel.confirmMode {
		return
	}
	channel.confirmLock.Lock()
	defer channel.confirmLock.Unlock()
	channel.statusLock.Lock()
	defer channel.statusLock.Unlock()

	if channel.status == channelClosed {
		return
	}
	channel.confirmQueue = append(channel.confirmQueue, meta)
}

func (channel *Channel) sendConfirms() {
	tick := time.Tick(20 * time.Millisecond)
	channel.statusLock.Lock()
	defer channel.statusLock.Unlock()
	for range tick {
		if channel.status == channelClosed {
			return
		}
		channel.confirmLock.Lock()
		currentConfirms := channel.confirmQueue
		channel.confirmQueue = make([]*amqp.ConfirmMeta, 0)
		channel.confirmLock.Unlock()

		for _, confirm := range currentConfirms {
			channel.SendMethod(&amqp.BasicAck{
				DeliveryTag: confirm.DeliveryTag,
				Multiple:    false,
			})
		}
	}
}

func (channel *Channel) addConsumer(method *amqp.BasicConsume) (cmr *consumer.Consumer, err *amqp.Error) {
	channel.cmrLock.Lock()
	defer channel.cmrLock.Unlock()

	var qu *queue.Queue
	if qu, err = channel.getQueueWithError(method.Queue, method); err != nil {
		return nil, err
	}

	var consumerQos []*qos.AmqpQos
	if channel.server.protoVersion == amqp.Proto091 {
		consumerQos = []*qos.AmqpQos{channel.qos, channel.conn.qos}
	} else {
		cmrQos := channel.consumerQos.Copy()
		consumerQos = []*qos.AmqpQos{channel.qos, cmrQos}
	}

	cmr = consumer.NewConsumer(method.Queue, method.ConsumerTag, method.NoAck, channel, qu, consumerQos)
	if _, ok := channel.consumers[cmr.Tag()]; ok {
		return nil, amqp.NewChannelError(amqp.NotAllowed, fmt.Sprintf("Consumer with tag '%s' already exists", cmr.Tag()), method.ClassIdentifier(), method.MethodIdentifier())
	}

	if quErr := qu.AddConsumer(cmr, method.Exclusive); quErr != nil {
		return nil, amqp.NewChannelError(amqp.AccessRefused, quErr.Error(), method.ClassIdentifier(), method.MethodIdentifier())
	}
	channel.consumers[cmr.Tag()] = cmr

	return cmr, nil
}

func (channel *Channel) removeConsumer(cTag string) {
	channel.cmrLock.Lock()
	defer channel.cmrLock.Unlock()
	if cmr, ok := channel.consumers[cTag]; ok {
		cmr.Stop()
		delete(channel.consumers, cmr.Tag())
	}
}

func (channel *Channel) close() {
	channel.cmrLock.Lock()
	for _, cmr := range channel.consumers {
		cmr.Stop()
		delete(channel.consumers, cmr.Tag())
		channel.logger.WithFields(log.Fields{
			"consumerTag": cmr.Tag(),
		}).Info("Consumer stopped")
	}
	channel.cmrLock.Unlock()
	if channel.id > 0 {
		channel.handleReject(0, true, true, &amqp.BasicNack{})
	}
	channel.statusLock.Lock()
	defer channel.statusLock.Unlock()
	channel.status = channelClosed
	channel.logger.Info("Channel closed")
}

func (channel *Channel) delete() {
	channel.closeCh <- true
	channel.statusLock.Lock()
	defer channel.statusLock.Unlock()
	channel.status = channelDelete
}

func (channel *Channel) updateQos(prefetchCount uint16, prefetchSize uint32, global bool) {
	if channel.server.protoVersion == amqp.Proto091 {
		if global {
			channel.conn.qos.Update(prefetchCount, prefetchSize)
		} else {
			channel.qos.Update(prefetchCount, prefetchSize)
		}
	} else {
		if global {
			channel.qos.Update(prefetchCount, prefetchSize)
		} else {
			channel.consumerQos.Update(prefetchCount, prefetchSize)
		}
	}
}

func (channel *Channel) GetQos() *qos.AmqpQos {
	return channel.qos
}

// NextDeliveryTag returns next delivery tag for current channel
func (channel *Channel) NextDeliveryTag() uint64 {
	return atomic.AddUint64(&channel.deliveryTag, 1)
}

func (channel *Channel) nextConfirmDeliveryTag() uint64 {
	return atomic.AddUint64(&channel.confirmDeliveryTag, 1)
}

// AddUnackedMessage add message to unacked queue
func (channel *Channel) AddUnackedMessage(dTag uint64, cTag string, queue string, message *amqp.Message) {
	channel.ackLock.Lock()
	defer channel.ackLock.Unlock()
	channel.ackStore[dTag] = &UnackedMessage{
		cTag:  cTag,
		msg:   message,
		queue: queue,
	}
}

func (channel *Channel) handleAck(method *amqp.BasicAck) *amqp.Error {
	channel.ackLock.Lock()
	defer channel.ackLock.Unlock()
	var uMsg *UnackedMessage
	var msgFound bool

	if method.Multiple {
		for tag, uMsg := range channel.ackStore {
			if method.DeliveryTag == 0 || tag <= method.DeliveryTag {
				channel.ackMsg(uMsg, tag)
			}
		}

		return nil
	}

	if uMsg, msgFound = channel.ackStore[method.DeliveryTag]; !msgFound {
		return amqp.NewChannelError(amqp.PreconditionFailed, fmt.Sprintf("Delivery tag [%d] not found", method.DeliveryTag), method.ClassIdentifier(), method.MethodIdentifier())
	}

	channel.ackMsg(uMsg, method.DeliveryTag)

	return nil
}

func (channel *Channel) ackMsg(unackedMessage *UnackedMessage, deliveryTag uint64) {
	delete(channel.ackStore, deliveryTag)
	q := channel.conn.GetVirtualHost().GetQueue(unackedMessage.queue)
	if q != nil {
		q.AckMsg(unackedMessage.msg)
	}

	channel.decQosAndConsumerNext(unackedMessage)
}

func (channel *Channel) handleReject(deliveryTag uint64, multiple bool, requeue bool, method amqp.Method) *amqp.Error {
	channel.ackLock.Lock()
	defer channel.ackLock.Unlock()
	var uMsg *UnackedMessage
	var msgFound bool

	if multiple {
		deliveryTags := make([]uint64, 0)
		for dTag := range channel.ackStore {
			deliveryTags = append(deliveryTags, dTag)
		}
		sort.Slice(
			deliveryTags,
			func(i, j int) bool {
				return deliveryTags[i] > deliveryTags[j]
			},
		)
		for _, tag := range deliveryTags {
			if deliveryTag == 0 || tag <= deliveryTag {
				channel.rejectMsg(channel.ackStore[tag], tag, requeue)
			}
		}

		return nil
	}

	if uMsg, msgFound = channel.ackStore[deliveryTag]; !msgFound {
		return amqp.NewChannelError(amqp.PreconditionFailed, fmt.Sprintf("Delivery tag [%d] not found", deliveryTag), method.ClassIdentifier(), method.MethodIdentifier())
	}

	channel.rejectMsg(uMsg, deliveryTag, requeue)

	return nil
}

func (channel *Channel) rejectMsg(unackedMessage *UnackedMessage, deliveryTag uint64, requeue bool) {
	delete(channel.ackStore, deliveryTag)
	qu := channel.conn.GetVirtualHost().GetQueue(unackedMessage.queue)

	if qu != nil {
		if requeue {
			qu.Requeue(unackedMessage.msg)
		} else {
			qu.AckMsg(unackedMessage.msg)
		}
	} else {
		// TODO When a queue is deleted any pending messages are sent to a dead­letter
	}

	channel.decQosAndConsumerNext(unackedMessage)
}

func (channel *Channel) decQosAndConsumerNext(unackedMessage *UnackedMessage) {
	channel.cmrLock.RLock()
	if cmr, ok := channel.consumers[unackedMessage.cTag]; ok {
		cmr.Consume()

		for _, amqpQos := range cmr.Qos() {
			amqpQos.Dec(1, uint32(unackedMessage.msg.BodySize))
		}
	} else {
		channel.qos.Dec(1, uint32(unackedMessage.msg.BodySize))
		channel.conn.qos.Dec(1, uint32(unackedMessage.msg.BodySize))
	}
	channel.cmrLock.RUnlock()
}

func (channel *Channel) getExchangeWithError(exchangeName string, method amqp.Method) (ex *exchange.Exchange, err *amqp.Error) {
	ex = channel.conn.GetVirtualHost().GetExchange(exchangeName)
	if ex == nil {
		return nil, amqp.NewChannelError(
			amqp.NotFound,
			fmt.Sprintf("exchange '%s' not found", exchangeName),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}
	return ex, nil
}

func (channel *Channel) getQueueWithError(queueName string, method amqp.Method) (queue *queue.Queue, err *amqp.Error) {
	qu := channel.conn.GetVirtualHost().GetQueue(queueName)
	if qu == nil || !qu.IsActive() {
		return nil, amqp.NewChannelError(
			amqp.NotFound,
			fmt.Sprintf("queue '%s' not found", queueName),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}
	return qu, nil
}

func (channel *Channel) checkQueueLockWithError(qu *queue.Queue, method amqp.Method) *amqp.Error {
	if qu == nil {
		return nil
	}
	if qu.IsExclusive() && qu.ConnID() != channel.conn.id {
		return amqp.NewChannelError(
			amqp.ResourceLocked,
			fmt.Sprintf("queue '%s' is locked to another connection", qu.GetName()),
			method.ClassIdentifier(),
			method.MethodIdentifier(),
		)
	}

	return nil
}

func (channel *Channel) isActive() bool {
	return channel.active
}

func (channel *Channel) changeFlow(active bool) {
	if channel.active == active {
		return
	}
	channel.active = active

	channel.cmrLock.RLock()
	if channel.active {
		for _, cmr := range channel.consumers {
			cmr.UnPause()
			cmr.Consume()
		}
	} else {
		for _, cmr := range channel.consumers {
			cmr.Pause()
		}
	}
	channel.cmrLock.RUnlock()
}

// GetConsumersCount returns consumers count on channel
func (channel *Channel) GetConsumersCount() int {
	return len(channel.consumers)
}
