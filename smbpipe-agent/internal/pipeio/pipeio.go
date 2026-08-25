// Package pipeio wraps raw named-pipe handles in overlapped Win32 I/O with
// per-operation deadlines, and creates pipe instances under a fixed DACL.
//
// Everything here operates on golang.org/x/sys/windows handles; callers own
// the handle lifecycle (ConnectNamedPipe / FlushFileBuffers / Disconnect /
// CloseHandle stay with the connection owner in package main).
package pipeio

import (
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrTimedOut is returned when an operation exceeds its deadline. The
// underlying operation is cancelled via CancelIoEx before returning.
var ErrTimedOut = errors.New("pipe I/O deadline exceeded")

// sddlAdminsSystemOnly: GENERIC_ALL for BUILTIN\Administrators and
// NT AUTHORITY\SYSTEM only, protected against inheritance.
const sddlAdminsSystemOnly = "D:P(A;;GA;;;BA)(A;;GA;;;SY)"

// Listen creates one listening instance of a byte-mode duplex overlapped
// pipe. first adds FILE_FLAG_FIRST_PIPE_INSTANCE so a second process cannot
// silently pre-create the same name (NPFS hands clients out FIFO, which
// enables instance-hijack races otherwise).
func Listen(name string, first bool, inputBufferSize, outputBufferSize int) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(sddlAdminsSystemOnly)
	if err != nil {
		return 0, fmt.Errorf("parse SDDL %q: %w", sddlAdminsSystemOnly, err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      0,
		SecurityDescriptor: sd,
	}

	openMode := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		openMode |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}

	h, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(name),
		openMode,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		uint32(outputBufferSize),
		uint32(inputBufferSize),
		0,
		sa,
	)
	runtime.KeepAlive(sd)
	if err != nil {
		return 0, err
	}
	return h, nil
}

type startFunc func(ol *windows.Overlapped) error
type completeFunc func(ol *windows.Overlapped) (uint32, error)

func getResult(h windows.Handle) completeFunc {
	return func(ol *windows.Overlapped) (uint32, error) {
		var n uint32
		err := windows.GetOverlappedResult(h, ol, &n, false)
		return n, err
	}
}

// Op runs one asynchronous pipe operation under a deadline: start issues it,
// complete extracts the transferred byte count once it finishes. Timed-out
// operations are cancelled with CancelIoEx.
func Op(h windows.Handle, timeout time.Duration, start startFunc, complete completeFunc) (uint32, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	ol := &windows.Overlapped{HEvent: event}

	err = start(ol)
	if err == nil {
		return complete(ol)
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}

	switch status, werr := windows.WaitForSingleObject(event, uint32(timeout/time.Millisecond)); {
	case werr != nil:
		return 0, werr
	case status == uint32(windows.WAIT_TIMEOUT):
		windows.CancelIoEx(h, ol)
		return 0, fmt.Errorf("%w (%v)", ErrTimedOut, timeout)
	default:
		return complete(ol)
	}
}

// Connect waits for a client on h. ERROR_PIPE_CONNECTED (client bound between
// Listen and Connect) is reported as success.
func Connect(h windows.Handle, timeout time.Duration) error {
	_, err := Op(h, timeout,
		func(ol *windows.Overlapped) error { return windows.ConnectNamedPipe(h, ol) },
		getResult(h))
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return err
	}
	return nil
}

// ReadFull reads exactly len(buf) bytes, issuing as many timed operations as
// needed. Each issued operation gets a fresh timeout window.
func ReadFull(h windows.Handle, buf []byte, timeout time.Duration) error {
	total := 0
	for total < len(buf) {
		n, err := Op(h, timeout,
			func(ol *windows.Overlapped) error { return windows.ReadFile(h, buf[total:], nil, ol) },
			getResult(h))
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("unexpected end of pipe stream")
		}
		total += int(n)
	}
	return nil
}

// WriteAll writes all of data, issuing as many timed operations as needed.
func WriteAll(h windows.Handle, data []byte, timeout time.Duration) error {
	total := 0
	for total < len(data) {
		n, err := Op(h, timeout,
			func(ol *windows.Overlapped) error { return windows.WriteFile(h, data[total:], nil, ol) },
			getResult(h))
		if err != nil {
			return err
		}
		total += int(n)
	}
	return nil
}

