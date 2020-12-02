package amqp

import (
	"bytes"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/pool"
	"sync/atomic"
	"time"
)

var emptyMessageBufferPool = pool.NewBufferPool(0)

// Table - simple amqp-table implementation
type Table map[string]interface{}

// Decimal represents amqp-decimal data
type Decimal struct {
	Scale uint8
	Value int32
}

// Frame is raw frame
type Frame struct {
	ChannelID  uint16
	Type       byte
	CloseAfter bool
	Sync       bool
	Payload    []byte
}

// ContentHeader represents amqp-message content-header
type ContentHeader struct {
	BodySize      uint64
	ClassID       uint16
	Weight        uint16
	propertyFlags uint16
	PropertyList  *BasicPropertyList
}

// ConfirmMeta store information for check confirms and send confirm-acks
type ConfirmMeta struct {
	ChanID           uint16
	ConnID           uint64
	DeliveryTag      uint64
	ExpectedConfirms int
	ActualConfirms   int
}

// CanConfirm returns is message can be confirmed
func (meta *ConfirmMeta) CanConfirm() bool {
	return meta.ActualConfirms == meta.ExpectedConfirms
}

// Message represents amqp-message and meta-data
type Message struct {
	ID            uint64
	BodySize      uint64
	DeliveryCount uint32
	Mandatory     bool
	Immediate     bool
	Exchange      string
	RoutingKey    string
	ConfirmMeta   *ConfirmMeta
	Header        *ContentHeader
	Body          []*Frame
}

// when server restart we can't start again count messages from 0
var msgID = uint64(time.Now().UnixNano())

// NewMessage returns new message instance
func NewMessage(method *BasicPublish) *Message {
	return &Message{
		Exchange:      method.Exchange,
		RoutingKey:    method.RoutingKey,
		Mandatory:     method.Mandatory,
		Immediate:     method.Immediate,
		BodySize:      0,
		DeliveryCount: 0,
	}
}

// IsPersistent check if message should be persisted
func (m *Message) IsPersistent() bool {
	deliveryMode := m.Header.PropertyList.DeliveryMode
	return deliveryMode != nil && *deliveryMode == 2
}

// GenerateSeq returns next message ID
func (m *Message) GenerateSeq() {
	if m.ID == 0 {
		m.ID = atomic.AddUint64(&msgID, 1)
	}
}

// Append appends new body-frame into message and increase bodySize
func (m *Message) Append(body *Frame) {
	m.Body = append(m.Body, body)
	m.BodySize += uint64(len(body.Payload))
}

// Marshal converts message into bytes to store into db
func (m *Message) Marshal(protoVersion string) (data []byte, err error) {
	buffer := emptyMessageBufferPool.Get()
	defer emptyMessageBufferPool.Put(buffer)

	if err = WriteLonglong(buffer, m.ID); err != nil {
		return nil, err
	}

	if err = WriteContentHeader(buffer, m.Header, protoVersion); err != nil {
		return nil, err
	}
	if err = WriteShortstr(buffer, m.Exchange); err != nil {
		return nil, err
	}
	if err = WriteShortstr(buffer, m.RoutingKey); err != nil {
		return nil, err
	}

	for _, frame := range m.Body {
		if err = WriteFrame(buffer, frame); err != nil {
			return nil, err
		}
	}

	data = make([]byte, buffer.Len())
	copy(data, buffer.Bytes())
	return
}

// Unmarshal restore message entity from bytes
func (m *Message) Unmarshal(buffer []byte, protoVersion string) (err error) {
	reader := bytes.NewReader(buffer)
	if m.ID, err = ReadLonglong(reader); err != nil {
		return err
	}

	if m.Header, err = ReadContentHeader(reader, protoVersion); err != nil {
		return err
	}
	if m.Exchange, err = ReadShortstr(reader); err != nil {
		return err
	}
	if m.RoutingKey, err = ReadShortstr(reader); err != nil {
		return err
	}

	for m.BodySize < m.Header.BodySize {
		body, errFrame := ReadFrame(reader)
		if errFrame != nil {
			return errFrame
		}
		m.Append(body)
	}

	return nil
}

// Constants to detect connection or channel error thrown
const (
	ErrorOnConnection = iota
	ErrorOnChannel
)

// Error represents AMQP-error data
type Error struct {
	ReplyCode uint16
	ReplyText string
	ClassID   uint16
	MethodID  uint16
	ErrorType int
}

// NewConnectionError returns new connection error. If caused - connection should be closed
func NewConnectionError(code uint16, text string, classID uint16, methodID uint16) *Error {
	err := &Error{
		ReplyCode: code,
		ReplyText: ConstantsNameMap[code] + " - " + text,
		ClassID:   classID,
		MethodID:  methodID,
		ErrorType: ErrorOnConnection,
	}

	return err
}

// NewChannelError returns new channel error& If caused - channel should be closed
func NewChannelError(code uint16, text string, classID uint16, methodID uint16) *Error {
	err := &Error{
		ReplyCode: code,
		ReplyText: ConstantsNameMap[code] + " - " + text,
		ClassID:   classID,
		MethodID:  methodID,
		ErrorType: ErrorOnChannel,
	}

	return err
}
