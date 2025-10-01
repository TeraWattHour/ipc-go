package structures

import "sync"

type CircularBuffer[K comparable, V any] struct {
	lock     sync.RWMutex
	mappings map[K]V
	buffer   []*K
	cursor   uint
	size     uint
}

func NewCircularBuffer[K comparable, V any](size uint) CircularBuffer[K, V] {
	return CircularBuffer[K, V]{
		lock:     sync.RWMutex{},
		mappings: make(map[K]V, size),
		buffer:   make([]*K, size),
		cursor:   0,
		size:     size,
	}
}

func (b *CircularBuffer[K, V]) Get(key K) (V, bool) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	value, ok := b.mappings[key]
	return value, ok
}

func (b *CircularBuffer[K, V]) Insert(key K, value V) bool {
	b.lock.Lock()
	defer b.lock.Unlock()

	if _, ok := b.mappings[key]; ok {
		return false
	}

	if b.cursor+1 >= b.size {
		b.cursor = 0
	} else {
		b.cursor += 1
	}

	replaced := b.buffer[b.cursor]
	if replaced != nil {
		delete(b.mappings, *replaced)
	}

	b.buffer[b.cursor] = &key
	b.mappings[key] = value

	return true
}
