package interfaces

import (
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
)

// Channel represents base channel public interface
type Channel interface {
	SendContent(method amqp.Method, message *amqp.Message)
	SendMethod(method amqp.Method)
	NextDeliveryTag() uint64
	AddUnackedMessage(dTag uint64, cTag string, queue string, message *amqp.Message)
}

// Consumer represents base consumer public interface
type Consumer interface {
	Consume() bool
	Tag() string
	Cancel()
}

// OpSet identifier for set data into storeage
const OpSet = 1

// OpDel identifier for delete data from storage
const OpDel = 2

// Operation represents structure to set/del from storage
type Operation struct {
	Key   string
	Value []byte
	Op    byte
}

// DbStorage represent base db storage interface
type DbStorage interface {
	Set(key string, value []byte) (err error)
	Del(key string) (err error)
	Get(key string) (value []byte, err error)
	Iterate(fn func(key []byte, value []byte))
	IterateByPrefix(prefix []byte, limit uint64, fn func(key []byte, value []byte)) uint64
	IterateByPrefixFrom(prefix []byte, from []byte, limit uint64, fn func(key []byte, value []byte)) uint64
	DeleteByPrefix(prefix []byte)
	KeysByPrefixCount(prefix []byte) uint64
	ProcessBatch(batch []*Operation) (err error)
	Close() error
}

// MsgStorage represent interface for messages storage
type MsgStorage interface {
	Del(message *amqp.Message, queue string) error
	PurgeQueue(queue string)
	Add(message *amqp.Message, queue string) error
	Update(message *amqp.Message, queue string) error
	IterateByQueueFromMsgID(queue string, msgID uint64, limit uint64, fn func(message *amqp.Message)) uint64
	GetQueueLength(queue string) uint64
}
