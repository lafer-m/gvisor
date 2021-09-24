// Copyright 2021 The gVisor Authors.
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

//go:build linux
// +build linux

package sharedmem

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/sys/unix"
)

const (
	// defaultQueueDataSize is the size of the shared memory data region that holds the
	// scatter/gather buffers.
	defaultQueueDataSize = 1 << 20 // 1MiB
	// defaultQueuePipeSize needs to be large enough For the descriptors to cover the
	// whole range of defaultQueueDataSize.
	defaultQueuePipeSize = 64 << 10 // 64KiB
	// defaultSharedDataSize is the size of the sharedData region used to enable/disable
	// notifications.
	defaultSharedDataSize = 4096
)

// A QueuePair represents a pair of TX/RX queues.
type QueuePair struct {
	// txCfg is the QueueConfig to be used for transmit queue.
	txCfg QueueConfig

	// rxCfg is the QueueConfig to be used for receive queue.
	rxCfg QueueConfig
}

// NewQueuePair creates a shared memory QueuePair.
func NewQueuePair() (*QueuePair, error) {
	txCfg, err := createQueueFDs(queueSizes{
		dataSize:       defaultQueueDataSize,
		txPipeSize:     defaultQueuePipeSize,
		rxPipeSize:     defaultQueuePipeSize,
		sharedDataSize: defaultSharedDataSize,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create tx queue: %s", err)
	}

	rxCfg, err := createQueueFDs(queueSizes{
		dataSize:       defaultQueueDataSize,
		txPipeSize:     defaultQueuePipeSize,
		rxPipeSize:     defaultQueuePipeSize,
		sharedDataSize: defaultSharedDataSize,
	})

	if err != nil {
		closeFDs(txCfg)
		return nil, fmt.Errorf("failed to create rx queue: %s", err)
	}

	return &QueuePair{
		txCfg: txCfg,
		rxCfg: rxCfg,
	}, nil
}

// Close closes underlying tx/rx queue fds.
func (q *QueuePair) Close() {
	closeFDs(q.txCfg)
	closeFDs(q.rxCfg)
}

// TXQueueConfig returns the QueueConfig for the receive queue.
func (q *QueuePair) TXQueueConfig() QueueConfig {
	return q.txCfg
}

// RXQueueConfig returns the QueueConfig for the transmit queue.
func (q *QueuePair) RXQueueConfig() QueueConfig {
	return q.rxCfg
}

type queueSizes struct {
	dataSize       int64
	txPipeSize     int64
	rxPipeSize     int64
	sharedDataSize int64
}

func createQueueFDs(s queueSizes) (QueueConfig, error) {
	success := false
	var fd uintptr
	var dataFD, txPipeFD, rxPipeFD, sharedDataFD int
	defer func() {
		if success {
			return
		}
		closeFDs(QueueConfig{
			EventFD:      int(fd),
			DataFD:       dataFD,
			TxPipeFD:     txPipeFD,
			RxPipeFD:     rxPipeFD,
			SharedDataFD: sharedDataFD,
		})
	}()
	fd, _, errno := unix.RawSyscall(unix.SYS_EVENTFD2, 0, 0, 0)
	if errno != 0 {
		return QueueConfig{}, fmt.Errorf("eventfd failed: %v", error(errno))
	}
	dataFD, err := createFile(s.dataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create dataFD: %s", err)
	}
	txPipeFD, err = createFile(s.txPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create txPipeFD: %s", err)
	}
	rxPipeFD, err = createFile(s.rxPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create rxPipeFD: %s", err)
	}
	sharedDataFD, err = createFile(s.sharedDataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create sharedDataFD: %s", err)
	}
	success = true
	return QueueConfig{
		EventFD:      int(fd),
		DataFD:       dataFD,
		TxPipeFD:     txPipeFD,
		RxPipeFD:     rxPipeFD,
		SharedDataFD: sharedDataFD,
	}, nil
}

func createFile(size int64, initQueue bool) (fd int, err error) {
	// tmpDir, ok := os.LookupEnv("TEST_TMPDIR")
	// if !ok {
	// tmpDir = os.Getenv("TMPDIR")
	// }
	// USPS throws a fit if the backing memory for the queue fds are not
	// /dev/shm unless we enable a test only flag.
	tmpDir := "/dev/shm/"
	f, err := ioutil.TempFile(tmpDir, "sharedmem_test")
	if err != nil {
		return -1, fmt.Errorf("TempFile failed: %v", err)
	}
	defer f.Close()
	unix.Unlink(f.Name())

	if initQueue {
		// Write the "slot-free" flag in the initial queue.
		_, err := f.WriteAt([]byte{0, 0, 0, 0, 0, 0, 0, 0x80}, 0)
		if err != nil {
			return -1, fmt.Errorf("WriteAt failed: %v", err)
		}
	}

	fd, err = unix.Dup(int(f.Fd()))
	if err != nil {
		return -1, fmt.Errorf("unix.Dup(%d) failed: %v", f.Fd(), err)
	}

	if err := unix.Ftruncate(fd, size); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("ftruncate(%d, %d) failed: %v", fd, size, err)
	}

	return fd, nil
}

func closeFDs(c QueueConfig) {
	unix.Close(c.DataFD)
	unix.Close(c.EventFD)
	unix.Close(c.TxPipeFD)
	unix.Close(c.RxPipeFD)
	unix.Close(c.SharedDataFD)
}
