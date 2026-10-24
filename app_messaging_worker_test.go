// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type messagingWorkerTestQueue struct {
	claim func(context.Context) (*messagingsqlite.Message, error)
	ack   func(context.Context, int64, string) error
}

func (q messagingWorkerTestQueue) Claim(ctx context.Context) (*messagingsqlite.Message, error) {
	return q.claim(ctx)
}
func (q messagingWorkerTestQueue) Acknowledge(ctx context.Context, id int64, lease string) error {
	return q.ack(ctx, id, lease)
}

func messagingWorkerTestMessage() *messagingsqlite.Message {
	return &messagingsqlite.Message{ID: 17, Lease: "private-lease", LeaseExpiresAt: time.Now().Add(time.Minute).Unix(), Subject: "private-subject", Body: "private-body", Recipients: []string{"private@example.test"}}
}

func TestSQLiteMessagingWorkerDeliveryBudget(t *testing.T) {
	for _, budget := range []string{"full", "short", "expired", "missing"} {
		t.Run(budget, func(t *testing.T) {
			message := messagingWorkerTestMessage()
			if budget == "short" {
				message.LeaseExpiresAt = time.Now().Add(9 * time.Second).Unix()
			}
			if budget == "expired" {
				message.LeaseExpiresAt = time.Now().Add(2 * time.Second).Unix()
			}
			if budget == "missing" {
				message.LeaseExpiresAt = 0
			}
			sent, acked := 0, 0
			cred := &credentials.GenericCredential{Name: "smtp", Username: "private-user", Password: "private-password"}
			worker := &sqliteMessagingWorker{credentials: cred}
			worker.queue = messagingWorkerTestQueue{
				claim: func(ctx context.Context) (*messagingsqlite.Message, error) {
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > messagingQueueTimeout {
						t.Error("unbounded claim")
					}
					return message, nil
				},
				ack: func(ctx context.Context, id int64, lease string) error {
					acked++
					deadline, ok := ctx.Deadline()
					if ctx.Err() != nil || !ok || time.Until(deadline) > messagingQueueTimeout || id != message.ID || lease != message.Lease {
						t.Error("invalid acknowledgement boundary")
					}
					return nil
				},
			}
			worker.send = func(ctx context.Context, input *messaging.SendInput) error {
				sent++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > messagingDeliveryTimeout || deadline.After(time.Unix(message.LeaseExpiresAt, 0).Add(-messagingQueueTimeout)) {
					t.Error("delivery exceeds budget")
				}
				if input.Subject != message.Subject || input.Body != message.Body || input.Recipients[0] != message.Recipients[0] || input.Credentials != cred {
					t.Error("message or transport credential changed")
				}
				input.Recipients[0] = "changed@example.test"
				return nil
			}
			delivered := worker.deliver(t.Context())
			want := budget == "full" || budget == "short"
			if delivered != want || sent != acked || (sent == 1) != want || message.Recipients[0] != "private@example.test" {
				t.Fatalf("delivery contract: result=%v sent=%d ack=%d", delivered, sent, acked)
			}
		})
	}
}

func TestSQLiteMessagingWorkerFailureAndRedaction(t *testing.T) {
	for _, phase := range []string{"empty", "claim", "nil", "delivery", "ack"} {
		t.Run(phase, func(t *testing.T) {
			core, observed := observer.New(zap.WarnLevel)
			sent, acked := 0, 0
			privateError := errors.New("private-body private@example.test private-lease private-password")
			worker := &sqliteMessagingWorker{logger: zap.New(core)}
			worker.queue = messagingWorkerTestQueue{
				claim: func(context.Context) (*messagingsqlite.Message, error) {
					switch phase {
					case "empty":
						return nil, messagingsqlite.ErrEmpty
					case "claim":
						return nil, privateError
					case "nil":
						return nil, nil
					}
					return messagingWorkerTestMessage(), nil
				},
				ack: func(context.Context, int64, string) error { acked++; return privateError },
			}
			worker.send = func(context.Context, *messaging.SendInput) error {
				sent++
				if phase == "delivery" {
					return privateError
				}
				return nil
			}
			if worker.deliver(t.Context()) {
				t.Error("failed attempt reported successful")
			}
			if phase == "delivery" && acked != 0 {
				t.Error("acknowledged failed/uncertain delivery")
			}
			if (phase == "claim" || phase == "empty" || phase == "nil") && sent != 0 {
				t.Error("sent without a claim")
			}
			for _, entry := range observed.All() {
				if strings.Contains(entry.Message, "private") || len(entry.Context) != 0 {
					t.Error("private delivery diagnostic leaked")
				}
			}
			if phase == "empty" && observed.Len() != 0 {
				t.Error("empty polling logged failure")
			}
		})
	}
}

func TestSQLiteMessagingWorkerAcknowledgesAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	acknowledged := false
	worker := &sqliteMessagingWorker{
		queue: messagingWorkerTestQueue{
			claim: func(context.Context) (*messagingsqlite.Message, error) { return messagingWorkerTestMessage(), nil },
			ack:   func(ctx context.Context, _ int64, _ string) error { acknowledged = ctx.Err() == nil; return nil },
		},
		send: func(context.Context, *messaging.SendInput) error { cancel(); return nil },
	}
	if !worker.deliver(ctx) || !acknowledged {
		t.Fatal("successful delivery lost bounded cleanup acknowledgement")
	}
}

func TestSQLiteMessagingWorkerStartStop(t *testing.T) {
	for _, phase := range []string{"claim", "delivery", "empty", "never_started"} {
		t.Run(phase, func(t *testing.T) {
			entered := make(chan struct{})
			var once sync.Once
			var calls atomic.Int64
			enter := func() { once.Do(func() { close(entered) }) }
			worker := &sqliteMessagingWorker{
				queue: messagingWorkerTestQueue{
					claim: func(ctx context.Context) (*messagingsqlite.Message, error) {
						calls.Add(1)
						if phase == "claim" {
							enter()
							<-ctx.Done()
							return nil, ctx.Err()
						}
						if phase == "empty" {
							enter()
							return nil, messagingsqlite.ErrEmpty
						}
						return messagingWorkerTestMessage(), nil
					},
					ack: func(context.Context, int64, string) error { t.Error("unexpected acknowledgement"); return nil },
				},
				send: func(ctx context.Context, _ *messaging.SendInput) error { enter(); <-ctx.Done(); return ctx.Err() },
			}
			t.Cleanup(worker.stop)
			if phase == "never_started" {
				worker.stop()
				worker.start()
				if calls.Load() != 0 {
					t.Fatal("resurrected worker")
				}
				return
			}
			worker.start()
			worker.start()
			awaitLifecycle(t, entered, "messaging worker entry")
			done := make(chan struct{})
			go func() {
				var group sync.WaitGroup
				for range 3 {
					group.Go(worker.stop)
				}
				group.Wait()
				close(done)
			}()
			awaitLifecycle(t, done, "bounded worker cancellation")
			if calls.Load() != 1 {
				t.Fatal("duplicate worker or immediate failure retry", calls.Load())
			}
			worker.start()
			if calls.Load() != 1 {
				t.Fatal("worker resurrected after cleanup")
			}
		})
	}
}

func TestSQLiteMessagingWorkerDrainsProducersBeforeCancellation(t *testing.T) {
	app := provisionLifecycleApp(t, lifecycleConfig())
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	var once sync.Once
	worker := &sqliteMessagingWorker{
		queue: messagingWorkerTestQueue{
			claim: func(context.Context) (*messagingsqlite.Message, error) { return messagingWorkerTestMessage(), nil },
			ack:   func(context.Context, int64, string) error { return nil },
		},
		send: func(ctx context.Context, _ *messaging.SendInput) error {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			close(cancelled)
			return ctx.Err()
		},
	}
	app.messagingWorkers = []*sqliteMessagingWorker{worker}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	awaitLifecycle(t, entered, "delivery start")
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("request admission unavailable")
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	select {
	case <-cancelled:
		t.Fatal("worker cancelled before producer drain")
	default:
	}
	releaseOnce.Do(release)
	awaitLifecycle(t, done, "messaging app cleanup")
	select {
	case <-cancelled:
	default:
		t.Fatal("cleanup returned before worker stopped")
	}
}

func TestSQLiteMessagingWorkerConcurrentQueues(t *testing.T) {
	config := sqliteMessagingTestConfig(t)
	backend, err := config.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	queue := backend.(*messagingsqlite.Outbox)
	defer queue.Close()
	otherBackend, err := config.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	other := otherBackend.(*messagingsqlite.Outbox)
	defer other.Close()
	const count = 20
	for i := range count {
		if err := queue.Send(&messaging.SendInput{Subject: fmt.Sprint(i), Body: "plain body", Recipients: []string{"recipient@example.test"}}); err != nil {
			t.Fatal(err)
		}
	}
	delivered := make(chan string, count*2)
	acknowledged := make(chan error, count)
	claimFailures := make(chan error, count*2)
	send := func(_ context.Context, input *messaging.SendInput) error { delivered <- input.Subject; return nil }
	observe := func(outbox *messagingsqlite.Outbox) messagingQueue {
		return messagingWorkerTestQueue{
			claim: func(ctx context.Context) (*messagingsqlite.Message, error) {
				message, err := outbox.Claim(ctx)
				if err != nil && !errors.Is(err, messagingsqlite.ErrEmpty) && ctx.Err() == nil {
					select {
					case claimFailures <- err:
					default:
					}
				}
				return message, err
			},
			ack: func(ctx context.Context, id int64, lease string) error {
				err := outbox.Acknowledge(ctx, id, lease)
				acknowledged <- err
				return err
			},
		}
	}
	workers := []*sqliteMessagingWorker{{queue: observe(queue), send: send}, {queue: observe(other), send: send}}
	for _, worker := range workers {
		worker.start()
		t.Cleanup(worker.stop)
	}
	seen := make(map[string]bool)
	for range count {
		select {
		case subject := <-delivered:
			if seen[subject] {
				t.Fatal("concurrent workers duplicated live work")
			}
			seen[subject] = true
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent workers failed to finish")
		}
	}
	// Observe durable acknowledgements before cancellation. An empty claim also
	// includes leased rows and cannot by itself prove that delivery was removed.
	for range count {
		select {
		case err := <-acknowledged:
			if err != nil {
				t.Fatal("concurrent acknowledgement failed before worker shutdown", err)
			}
		case err := <-claimFailures:
			t.Fatal("concurrent claim failed before worker shutdown", err)
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent acknowledgements failed to finish")
		}
	}
	for _, worker := range workers {
		worker.stop()
	}
	select {
	case err := <-claimFailures:
		t.Fatal("live claim failed during contention", err)
	default:
	}
	select {
	case <-delivered:
		t.Fatal("extra delivery")
	default:
	}
	// Reopen for inspection: shutdown cancellation itself is not evidence that
	// a prior transaction did not commit, and should not be silently retried.
	reopened, err := config.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fresh := reopened.(*messagingsqlite.Outbox)
	defer fresh.Close()
	if _, err := fresh.Claim(t.Context()); !errors.Is(err, messagingsqlite.ErrEmpty) {
		t.Fatal("successful delivery was not acknowledged", err)
	}
}
