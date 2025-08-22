package queue_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/brickingsoft/rio/pkg/liburing/aio/queue"
)

type QueueEntry struct {
	N int
}

func (e *QueueEntry) String() string {
	return fmt.Sprintf("%d", e.N)
}

func TestQueue(t *testing.T) {
	q := queue.New[QueueEntry]()
	wg := new(sync.WaitGroup)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(queue *queue.Queue[QueueEntry], i int, wg *sync.WaitGroup) {
			queue.Enqueue(&QueueEntry{N: i})
			wg.Done()
		}(q, i, wg)
	}
	wg.Wait()

	t.Log("length", q.Length())
	nn := make([]*QueueEntry, 0, 1)
	for {
		n := q.Dequeue()
		if n == nil {
			break
		}
		nn = append(nn, n)
	}
	t.Log("dequeue", nn)
	t.Log("length", q.Length(), q.Dequeue())

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(queue *queue.Queue[QueueEntry], i int, wg *sync.WaitGroup) {
			queue.Enqueue(&QueueEntry{N: i})
			wg.Done()
		}(q, i, wg)
	}
	wg.Wait()

	nn = make([]*QueueEntry, 5)
	peeked := q.PeekBatch(nn)
	t.Log("peeked", peeked, nn)
	t.Log("length", q.Length())
	q.Advance(peeked)
	t.Log("length", q.Length())

	nn = make([]*QueueEntry, 5)
	peeked = q.PeekBatch(nn)
	t.Log("peeked", peeked, nn)
	t.Log("length", q.Length())
	q.Advance(peeked)
	t.Log("length", q.Length())

	nn = make([]*QueueEntry, 0, 1)
	for {
		n := q.Dequeue()
		if n == nil {
			break
		}
		nn = append(nn, n)
	}
	t.Log("dequeue", nn)
	t.Log("length", q.Length())
}
