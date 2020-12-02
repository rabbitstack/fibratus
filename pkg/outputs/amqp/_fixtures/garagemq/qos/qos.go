package qos

import "sync"

// AmqpQos represents qos system
type AmqpQos struct {
	sync.Mutex
	prefetchCount uint16
	currentCount  uint16
	prefetchSize  uint32
	currentSize   uint32
}

// NewAmqpQos returns new instance of AmqpQos
func NewAmqpQos(prefetchCount uint16, prefetchSize uint32) *AmqpQos {
	return &AmqpQos{
		prefetchCount: prefetchCount,
		prefetchSize:  prefetchSize,
		currentCount:  0,
		currentSize:   0,
	}
}

// PrefetchCount returns prefetchCount
func (qos *AmqpQos) PrefetchCount() uint16 {
	return qos.prefetchCount
}

// PrefetchSize returns prefetchSize
func (qos *AmqpQos) PrefetchSize() uint32 {
	return qos.prefetchSize
}

// Update set new prefetchCount and prefetchSize
func (qos *AmqpQos) Update(prefetchCount uint16, prefetchSize uint32) {
	qos.prefetchCount = prefetchCount
	qos.prefetchSize = prefetchSize
}

// IsActive check is qos rules are active
// both prefetchSize and prefetchCount must be 0
func (qos *AmqpQos) IsActive() bool {
	return qos.prefetchCount != 0 || qos.prefetchSize != 0
}

// Inc increment current count and size
// Returns true if increment success
// Returns false if after increment size or count will be more than prefetchCount or prefetchSize
func (qos *AmqpQos) Inc(count uint16, size uint32) bool {
	qos.Lock()
	defer qos.Unlock()

	newCount := qos.currentCount + count
	newSize := qos.currentSize + size

	if (qos.prefetchCount == 0 || newCount <= qos.prefetchCount) && (qos.prefetchSize == 0 || newSize <= qos.prefetchSize) {
		qos.currentCount = newCount
		qos.currentSize = newSize
		return true
	}

	return false
}

// Dec decrement current count and size
func (qos *AmqpQos) Dec(count uint16, size uint32) {
	qos.Lock()
	defer qos.Unlock()

	if qos.currentCount < count {
		qos.currentCount = 0
	} else {
		qos.currentCount = qos.currentCount - count
	}

	if qos.currentSize < size {
		qos.currentSize = 0
	} else {
		qos.currentSize = qos.currentSize - size
	}
}

// Release reset current count and size
func (qos *AmqpQos) Release() {
	qos.Lock()
	defer qos.Unlock()
	qos.currentCount = 0
	qos.currentSize = 0
}

// Copy safe copy current qos instance to new one
func (qos *AmqpQos) Copy() *AmqpQos {
	qos.Lock()
	defer qos.Unlock()
	return &AmqpQos{
		prefetchCount: qos.prefetchCount,
		prefetchSize:  qos.prefetchSize,
		currentCount:  qos.currentCount,
		currentSize:   qos.currentSize,
	}
}
