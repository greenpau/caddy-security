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
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	"go.uber.org/zap"
)

const (
	messagingDeliveryTimeout = 15 * time.Second
	messagingQueueTimeout    = 5 * time.Second
	messagingPollInterval    = time.Second
)

type messagingQueue interface {
	Claim(context.Context) (*messagingsqlite.Message, error)
	Acknowledge(context.Context, int64, string) error
}

// sqliteMessagingWorker owns no queue: the app stops and joins it before closing
// the provider. Successful queue acceptance does not prove recipient delivery.
// SMTP acceptance followed by a lost acknowledgement can deliver twice.
type sqliteMessagingWorker struct {
	queue       messagingQueue
	send        func(context.Context, *messaging.SendInput) error
	credentials *credentials.GenericCredential
	logger      *zap.Logger
	mu          sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	stopped     bool
}

func (w *sqliteMessagingWorker) start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || w.done != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		w.run(ctx)
	}()
}

func (w *sqliteMessagingWorker) stop() {
	w.mu.Lock()
	w.stopped = true
	done := w.done
	if w.cancel != nil {
		w.cancel()
	}
	w.mu.Unlock()
	if done != nil {
		<-done
	}
}

func (w *sqliteMessagingWorker) run(ctx context.Context) {
	for ctx.Err() == nil {
		if w.deliver(ctx) {
			continue
		}
		timer := time.NewTimer(messagingPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// deliver attempts one claim. Failures remain leased: retrying an uncertain
// SMTP send or database mutation immediately can duplicate accepted work.
func (w *sqliteMessagingWorker) deliver(ctx context.Context) bool {
	claimCtx, cancel := context.WithTimeout(ctx, messagingQueueTimeout)
	message, err := w.queue.Claim(claimCtx)
	cancel()
	if err != nil {
		if !errors.Is(err, messagingsqlite.ErrEmpty) && ctx.Err() == nil {
			w.warn("SQLite messaging claim failed")
		}
		return false
	}
	if message == nil || ctx.Err() != nil {
		return false
	}
	// Claim's stored timestamp is authoritative; reserve time for acknowledgement
	// even if lock contention or scheduling used much of the lease already.
	deadline := time.Unix(message.LeaseExpiresAt, 0).Add(-messagingQueueTimeout)
	now := time.Now()
	if !deadline.After(now) {
		w.warn("SQLite messaging lease has insufficient delivery time")
		return false
	}
	if cap := now.Add(messagingDeliveryTimeout); cap.Before(deadline) {
		deadline = cap
	}
	deliveryCtx, cancel := context.WithDeadline(ctx, deadline)
	err = w.send(deliveryCtx, &messaging.SendInput{
		Subject: message.Subject, Body: message.Body,
		Recipients: append([]string(nil), message.Recipients...), Credentials: w.credentials,
	})
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			w.warn("SQLite messaging delivery failed")
		}
		return false
	}
	// Cancellation after SMTP success must still permit a bounded acknowledgement.
	// The provider remains open until this worker returns, including during cleanup.
	ackCtx, cancel := context.WithTimeout(context.Background(), messagingQueueTimeout)
	err = w.queue.Acknowledge(ackCtx, message.ID, message.Lease)
	cancel()
	if err != nil {
		w.warn("SQLite messaging acknowledgement failed")
		return false
	}
	return true
}

func (w *sqliteMessagingWorker) warn(message string) {
	if w.logger != nil {
		// No provider errors, payloads, recipient addresses, credentials or leases.
		w.logger.Warn(message)
	}
}
