package queue

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/config"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/interfaces"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/qos"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/safequeue"
	"sync"
	"sync/atomic"
)

// Queue is an implementation of the AMQP-queue entity
type Queue struct {
	safequeue.SafeQueue
	name        string
	connID      uint64
	exclusive   bool
	autoDelete  bool
	durable     bool
	cmrLock     sync.RWMutex
	consumers   []interfaces.Consumer
	consumeExcl bool
	call        chan struct{}
	wasConsumed bool
	shardSize   int
	actLock     sync.RWMutex
	active      bool
	// persistent storage
	// transient storage
	currentConsumer int
	autoDeleteQueue chan string
	queueLength     int64

	// lock for sync load swapped-messages from disk
	loadSwapLock           sync.Mutex
	maxMessagesInRAM       uint64
	lastStoredMsgID        uint64
	lastMemMsgID           uint64
	swappedToDisk          bool
	maybeLoadFromStorageCh chan struct{}
	wg                     *sync.WaitGroup
}

// NewQueue returns new instance of Queue
func NewQueue(name string, connID uint64, exclusive bool, autoDelete bool, durable bool, config config.Queue, msgStorageP interfaces.MsgStorage, msgStorageT interfaces.MsgStorage, autoDeleteQueue chan string) *Queue {
	return &Queue{
		SafeQueue:              *safequeue.NewSafeQueue(config.ShardSize),
		name:                   name,
		connID:                 connID,
		exclusive:              exclusive,
		autoDelete:             autoDelete,
		durable:                durable,
		call:                   make(chan struct{}, 1),
		maybeLoadFromStorageCh: make(chan struct{}, 1),
		wasConsumed:            false,
		active:                 false,
		shardSize:              1,
		maxMessagesInRAM:       1500,
		currentConsumer:        0,
		autoDeleteQueue:        autoDeleteQueue,
		swappedToDisk:          false,
		wg:                     &sync.WaitGroup{},
	}

}

// Start starts base queue loop to send events to consumers
// Current consumer to handle message from queue selected by round robin
func (queue *Queue) Start() error {
	queue.actLock.Lock()
	defer queue.actLock.Unlock()

	if queue.active {
		return nil
	}

	queue.active = true
	queue.wg.Add(1)
	go func() {
		defer queue.wg.Done()
		for range queue.call {
			func() {
				queue.cmrLock.RLock()
				defer queue.cmrLock.RUnlock()
				cmrCount := len(queue.consumers)
				for i := 0; i < cmrCount; i++ {
					if !queue.active {
						return
					}
					queue.currentConsumer = (queue.currentConsumer + 1) % cmrCount
					cmr := queue.consumers[queue.currentConsumer]
					if cmr.Consume() {
						return
					}
				}
			}()
		}
	}()

	queue.wg.Add(1)
	go func() {
		defer queue.wg.Done()
		for range queue.maybeLoadFromStorageCh {
			queue.mayBeLoadFromStorage()
		}
	}()

	return nil
}

// Stop stops main queue loop
// After stop no one can send or receive messages from queue
func (queue *Queue) Stop() error {
	queue.actLock.Lock()
	defer queue.actLock.Unlock()

	queue.active = false
	close(queue.maybeLoadFromStorageCh)
	close(queue.call)
	queue.wg.Wait()
	return nil
}

// GetName returns queue name
func (queue *Queue) GetName() string {
	return queue.name
}

// Push append message into queue tail and put it into message storage
// if queue is durable and message's persistent flag is true
func (queue *Queue) Push(message *amqp.Message) {
	queue.actLock.Lock()
	defer queue.actLock.Unlock()

	if !queue.active {
		return
	}

	atomic.AddInt64(&queue.queueLength, 1)

	message.GenerateSeq()

	persisted := false
	if queue.durable && message.IsPersistent() {
		persisted = true
	} else {
		if queue.SafeQueue.Length() > queue.maxMessagesInRAM || queue.swappedToDisk {
			persisted = true
		}

		if message.ConfirmMeta != nil {
			message.ConfirmMeta.ActualConfirms++
		}
	}

	if persisted && !queue.swappedToDisk && queue.SafeQueue.Length() > queue.maxMessagesInRAM {
		queue.swappedToDisk = true
		queue.lastStoredMsgID = message.ID
	}

	if queue.SafeQueue.Length() <= queue.maxMessagesInRAM && !queue.swappedToDisk {
		queue.SafeQueue.Push(message)
		queue.lastMemMsgID = message.ID
	}

	queue.callConsumers()
}

// Pop returns message from queue head without QOS check
func (queue *Queue) Pop() *amqp.Message {
	return queue.PopQos([]*qos.AmqpQos{})
}

// PopQos returns message from queue head with QOS check
func (queue *Queue) PopQos(qosList []*qos.AmqpQos) *amqp.Message {
	queue.actLock.RLock()
	if !queue.active {
		queue.actLock.RUnlock()
		return nil
	}
	queue.actLock.RUnlock()

	select {
	case queue.maybeLoadFromStorageCh <- struct{}{}:
	default:
	}

	queue.SafeQueue.Lock()
	var message *amqp.Message
	if message = queue.SafeQueue.HeadItem(); message != nil {
		allowed := true
		for _, q := range qosList {
			if !q.IsActive() {
				continue
			}
			if !q.Inc(1, uint32(message.BodySize)) {
				allowed = false
				break
			}
		}

		if allowed {
			queue.SafeQueue.DirtyPop()
			atomic.AddInt64(&queue.queueLength, -1)
		} else {
			message = nil
		}
	}
	queue.SafeQueue.Unlock()

	return message
}

func (queue *Queue) mayBeLoadFromStorage() {
	swappedToPersistent := true
	swappedToTransient := true

	currentLength := queue.SafeQueue.Length()
	needle := queue.maxMessagesInRAM - currentLength

	if currentLength >= queue.maxMessagesInRAM/2 || needle <= 0 || !queue.swappedToDisk {
		return
	}

	pMessages := make([]*amqp.Message, 0, needle)
	tMessages := make([]*amqp.Message, 0, needle)

	lastMemMsgID := queue.lastMemMsgID

	var wg sync.WaitGroup
	// 2 - search for transient and persistent
	wg.Add(2)

	go func() {
		wg.Done()
	}()

	go func() {
		wg.Done()
	}()

	wg.Wait()

	sortedMessages := queue.mergeSortedMessageSlices(pMessages, tMessages)
	sortedMessageslength := uint64(len(sortedMessages))

	var pos uint64
	if sortedMessageslength <= needle {
		pos = sortedMessageslength
	} else {
		pos = needle
	}

	for _, message := range sortedMessages[0:pos] {
		if message.ID == lastMemMsgID {
			continue
		}
		queue.SafeQueue.Push(message)
		queue.lastMemMsgID = message.ID
		queue.lastStoredMsgID = message.ID
		queue.callConsumers()
	}

	queue.swappedToDisk = swappedToPersistent || swappedToTransient
}

func (queue *Queue) mergeSortedMessageSlices(A, B []*amqp.Message) []*amqp.Message {
	result := make([]*amqp.Message, len(A)+len(B))

	idxA, idxB := 0, 0

	for i := 0; i < len(result); i++ {
		if idxA >= len(A) {
			result[i] = B[idxB]
			idxB++
			continue
		} else if idxB >= len(B) {
			result[i] = A[idxA]
			idxA++
			continue
		}

		if A[idxA].ID < B[idxB].ID {
			result[i] = A[idxA]
			idxA++
		} else {
			result[i] = B[idxB]
			idxB++
		}
	}

	return result
}

// AckMsg accept ack event for message
func (queue *Queue) AckMsg(message *amqp.Message) {
	queue.actLock.RLock()
	if !queue.active {
		queue.actLock.RUnlock()
		return
	}
	queue.actLock.RUnlock()

	if queue.durable && message.IsPersistent() {
		// TODO handle error
	}

}

// Requeue add message into queue head
func (queue *Queue) Requeue(message *amqp.Message) {
	queue.actLock.RLock()
	if !queue.active {
		queue.actLock.RUnlock()
		return
	}
	queue.actLock.RUnlock()

	message.DeliveryCount++
	queue.SafeQueue.PushHead(message)
	if queue.durable && message.IsPersistent() {
		// TODO handle error
	}

	atomic.AddInt64(&queue.queueLength, 1)

	queue.callConsumers()
}

// Purge clean queue and message storage for durable queues
func (queue *Queue) Purge() (length uint64) {
	queue.SafeQueue.Lock()
	defer queue.SafeQueue.Unlock()
	length = uint64(atomic.LoadInt64(&queue.queueLength))
	queue.SafeQueue.DirtyPurge()

	if queue.durable {
	}

	atomic.StoreInt64(&queue.queueLength, 0)
	return
}

// Delete cancel consumers and delete its messages from storage
func (queue *Queue) Delete(ifUnused bool, ifEmpty bool) (uint64, error) {
	queue.actLock.Lock()
	queue.cmrLock.Lock()
	queue.SafeQueue.Lock()
	defer queue.actLock.Unlock()
	defer queue.cmrLock.Unlock()
	defer queue.SafeQueue.Unlock()

	queue.active = false

	if ifUnused && len(queue.consumers) != 0 {
		return 0, errors.New("queue has consumers")
	}

	if ifEmpty && queue.SafeQueue.DirtyLength() != 0 {
		return 0, errors.New("queue has messages")
	}

	queue.cancelConsumers()
	length := uint64(atomic.LoadInt64(&queue.queueLength))

	if queue.durable {
	}

	return length, nil
}

// AddConsumer add consumer to consumer messages with exclusive check
func (queue *Queue) AddConsumer(consumer interfaces.Consumer, exclusive bool) error {
	queue.cmrLock.Lock()
	defer queue.cmrLock.Unlock()

	if !queue.active {
		return fmt.Errorf("queue is not active")
	}
	queue.wasConsumed = true

	if len(queue.consumers) != 0 && (queue.consumeExcl || exclusive) {
		return fmt.Errorf("queue is busy by %d consumers", len(queue.consumers))
	}

	if exclusive {
		queue.consumeExcl = true
	}

	queue.consumers = append(queue.consumers, consumer)

	queue.callConsumers()
	return nil
}

// RemoveConsumer remove consumer
// If it was last consumer and queue is auto-delete - queue will be removed
func (queue *Queue) RemoveConsumer(cTag string) {
	queue.cmrLock.Lock()
	defer queue.cmrLock.Unlock()

	for i, cmr := range queue.consumers {
		if cmr.Tag() == cTag {
			queue.consumers = append(queue.consumers[:i], queue.consumers[i+1:]...)
			break
		}
	}
	cmrCount := len(queue.consumers)
	if cmrCount == 0 {
		queue.currentConsumer = 0
		queue.consumeExcl = false
	} else {
		queue.currentConsumer = (queue.currentConsumer + 1) % cmrCount
	}

	if cmrCount == 0 && queue.wasConsumed && queue.autoDelete {
		queue.autoDeleteQueue <- queue.name
	}
}

// Send event to call next consumer, that it can receive next message
func (queue *Queue) callConsumers() {
	if !queue.active {
		return
	}
	select {
	case queue.call <- struct{}{}:
	default:
	}
}

func (queue *Queue) cancelConsumers() {
	for _, cmr := range queue.consumers {
		cmr.Cancel()
	}
}

// Length returns queue length
func (queue *Queue) Length() uint64 {
	return uint64(atomic.LoadInt64(&queue.queueLength))
}

// ConsumersCount returns consumers count
func (queue *Queue) ConsumersCount() int {
	queue.cmrLock.RLock()
	defer queue.cmrLock.RUnlock()
	return len(queue.consumers)
}

// EqualWithErr returns is given queue equal to current
func (queue *Queue) EqualWithErr(qB *Queue) error {
	errTemplate := "inequivalent arg '%s' for queue '%s': received '%t' but current is '%t'"
	if queue.durable != qB.IsDurable() {
		return fmt.Errorf(errTemplate, "durable", queue.name, qB.IsDurable(), queue.durable)
	}
	if queue.autoDelete != qB.autoDelete {
		return fmt.Errorf(errTemplate, "autoDelete", queue.name, qB.autoDelete, queue.autoDelete)
	}
	if queue.exclusive != qB.IsExclusive() {
		return fmt.Errorf(errTemplate, "exclusive", queue.name, qB.IsExclusive(), queue.exclusive)
	}
	return nil
}

// Marshal returns raw representation of queue to store into storage
func (queue *Queue) Marshal(protoVersion string) (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	if err = amqp.WriteShortstr(buf, queue.name); err != nil {
		return nil, err
	}

	var autoDelete byte
	if queue.autoDelete {
		autoDelete = 1
	} else {
		autoDelete = 0
	}

	if err = amqp.WriteOctet(buf, autoDelete); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal returns queue from storage raw bytes data
func (queue *Queue) Unmarshal(data []byte, protoVersion string) (err error) {
	buf := bytes.NewReader(data)
	if queue.name, err = amqp.ReadShortstr(buf); err != nil {
		return err
	}

	var autoDelete byte

	if autoDelete, err = amqp.ReadOctet(buf); err != nil {
		return err
	}
	queue.autoDelete = autoDelete > 0
	queue.durable = true
	return
}

// IsDurable returns is queue durable
func (queue *Queue) IsDurable() bool {
	return queue.durable
}

// IsExclusive returns is queue exclusive
func (queue *Queue) IsExclusive() bool {
	return queue.exclusive
}

// IsAutoDelete returns is queue should be deleted automatically
func (queue *Queue) IsAutoDelete() bool {
	return queue.autoDelete
}

// ConnID returns ID of connection that create this queue
func (queue *Queue) ConnID() uint64 {
	return queue.connID
}

// IsActive returns is queue's main loop is active
func (queue *Queue) IsActive() bool {
	return queue.active
}
