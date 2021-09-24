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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
)

// serverTx represents the server end of the sharedmem queue and is used to send
// packets to the peer in the buffers posted by the peer in the fillPipe.
type serverTx struct {
	// fillPipe represents the receive end of the pipe that carries the RxBuffers
	// posted by the peer.
	fillPipe pipe.Rx

	// completionPipe represents the transmit end of the pipe that carries the
	// descriptors for filled RxBuffers.
	completionPipe pipe.Tx

	// data represents the buffer area where the packet payload is held.
	data []byte

	// eventFD is used to notify the peer when fill requests are fulfilled.
	eventFD int

	// sharedData the memory region to use to enable/disable notifications.
	sharedData []byte
}

// init initializes all tstate needed by the serverTx queue based on the
// information provided.
//
// The caller always retains ownership of all file descriptors passed in. The
// queue implementation will duplicate any that it may need in the future.
func (s *serverTx) init(c *QueueConfig) error {
	// Map in all buffers.
	fillPipeMem, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}

	completionPipeMem, err := getBuffer(c.RxPipeFD)
	if err != nil {
		unix.Munmap(fillPipeMem)
		return err
	}

	data, err := getBuffer(c.DataFD)
	if err != nil {
		unix.Munmap(fillPipeMem)
		unix.Munmap(completionPipeMem)
		return err
	}

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		unix.Munmap(fillPipeMem)
		unix.Munmap(completionPipeMem)
		unix.Munmap(data)
		return err
	}

	// Duplicate the eventFD so that caller can close it but we can still
	// use it.
	efd, err := unix.Dup(c.EventFD)
	if err != nil {
		unix.Munmap(sharedData)
		unix.Munmap(fillPipeMem)
		unix.Munmap(completionPipeMem)
		unix.Munmap(data)
		return err
	}

	// Set the eventfd as non-blocking.
	if err := unix.SetNonblock(efd, true); err != nil {
		unix.Munmap(sharedData)
		unix.Munmap(fillPipeMem)
		unix.Munmap(completionPipeMem)
		unix.Munmap(data)
		unix.Close(efd)
		return err
	}

	s.fillPipe.Init(fillPipeMem)
	s.completionPipe.Init(completionPipeMem)
	s.data = data
	s.eventFD = efd
	s.sharedData = sharedData

	return nil
}

func (s *serverTx) cleanup() {
	unix.Munmap(s.fillPipe.Bytes())
	unix.Munmap(s.completionPipe.Bytes())
	unix.Munmap(s.data)
	unix.Munmap(s.sharedData)
	unix.Close(s.eventFD)
}

// fillPacket copies the data in the provided views into buffers pulled from the
// fillPipe and returns a slice of RxBuffers that contain the copied data as
// well as the total number of bytes copied.
//
// To avoid allocations the filledBuffers are appended to the buffers slice
// which will be grown as required.
func (s *serverTx) fillPacket(views []buffer.View, buffers []queue.RxBuffer) (filledBuffers []queue.RxBuffer, totalCopied uint32) {
	filledBuffers = buffers[:0]
	// fillBuffer copies as much of the views as possible into the provided buffer
	// and returns any left over views (if any).
	fillBuffer := func(buffer *queue.RxBuffer, views []buffer.View) (left []buffer.View) {
		if len(views) == 0 {
			return nil
		}
		availBytes := buffer.Size
		copied := uint64(0)
		for availBytes > 0 && len(views) > 0 {
			n := copy(s.data[buffer.Offset+copied:][:uint64(buffer.Size)-copied], views[0])
			views[0].TrimFront(n)
			if !views[0].IsEmpty() {
				break
			}
			views = views[1:]
			copied += uint64(n)
			availBytes -= uint32(n)
		}
		buffer.Size = uint32(copied)
		return views
	}

	for len(views) > 0 {
		var b []byte
		// Spin till we get a free buffer reposted by the peer.
		for {
			if b = s.fillPipe.Pull(); b != nil {
				break
			}
		}
		rxBuffer := queue.DecodeRxBufferHeader(b)
		// Copy the packet into the posted buffer.
		views = fillBuffer(&rxBuffer, views)
		totalCopied += rxBuffer.Size
		filledBuffers = append(filledBuffers, rxBuffer)
	}

	return filledBuffers, totalCopied
}

func (s *serverTx) transmit(views []buffer.View) bool {
	buffers := make([]queue.RxBuffer, 8)
	buffers, totalCopied := s.fillPacket(views, buffers)
	b := s.completionPipe.Push(queue.RxCompletionSize(len(buffers)))
	if b == nil {
		return false
	}
	queue.EncodeRxCompletion(b, totalCopied, 0 /* reserved */)
	for i := 0; i < len(buffers); i++ {
		queue.EncodeRxCompletionBuffer(b, i, buffers[i])
	}
	s.completionPipe.Flush()
	s.fillPipe.Flush()
	return true
}

func (s *serverTx) notify() {
	unix.Write(s.eventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})
}
