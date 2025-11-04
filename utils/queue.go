package utils

import (
	"iter"
	"sync"
)

type QueueEntry[T any] struct {
	Value T
	next  *QueueEntry[T]
}

type SafeQueue[T any] struct {
	head, tail *QueueEntry[T]
	mx         sync.Mutex
}

func NewQueue[T any]() *SafeQueue[T] {
	return &SafeQueue[T]{}
}

func (q *SafeQueue[T]) EnqueueTail(v T) {
	q.mx.Lock()
	defer q.mx.Unlock()
	if q.tail == nil {
		q.tail = &QueueEntry[T]{Value: v}
		q.head = q.tail
	} else {
		q.tail.next = &QueueEntry[T]{Value: v}
		q.tail = q.tail.next
	}
}

func (q *SafeQueue[T]) EnqueueHead(v T) {
	q.mx.Lock()
	defer q.mx.Unlock()
	if q.head == nil {
		q.head = &QueueEntry[T]{Value: v}
		q.tail = q.head
	} else {
		q.head = &QueueEntry[T]{Value: v, next: q.head}
	}
}

func (q *SafeQueue[T]) Dequeue() (T, bool) {
	q.mx.Lock()
	defer q.mx.Unlock()
	if q.head == nil {
		var t T
		return t, false
	}
	v := q.head.Value
	q.head = q.head.next
	if q.head == nil {
		q.tail = nil
	}
	return v, true
}

func (q *SafeQueue[T]) FillFromIter(iter iter.Seq[T]) {
	for v := range iter {
		q.EnqueueTail(v)
	}
}
