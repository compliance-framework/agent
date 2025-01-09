package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/nats-io/nats.go"
	"sync"
)

const NATS_RECONNECT_BUF_SIZE = 5 * 1024 * 1024

type NatsBus struct {
	logger hclog.Logger

	conn *nats.Conn
	mu   sync.Mutex
}

func NewNatsBus(logger hclog.Logger) *NatsBus {
	return &NatsBus{
		logger: logger,
	}
}

func (nb *NatsBus) Connect(server string) error {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	if nb.conn != nil {
		return errors.New("already connected")
	}

	c, err := nats.Connect(server, nats.ReconnectBufSize(NATS_RECONNECT_BUF_SIZE))
	if err != nil {
		return err
	}
	nb.conn = c

	return nil
}

// Not a method due to Golang limitations on generics there, so we just pass the bus as a parameter.
func Publish[T any](nb *NatsBus, msg T, topic string) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	fmt.Println("#####################")
	nb.logger.Trace("Publishing message", "topic", topic, "data", string(data))
	return nb.conn.Publish(topic, data)
}

func (nb *NatsBus) Close() {
	nb.conn.Close()
}
