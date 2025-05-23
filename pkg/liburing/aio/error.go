package aio

import (
	"context"
	"errors"
	"syscall"
)

var (
	ErrCanceled      = &CanceledError{}
	ErrTimeout       = &TimeoutError{}
	ErrFdUnavailable = errors.New("file descriptor unavailable")
	ErrOpInvalid     = errors.New("invalid operation")
)

func IsCanceled(err error) bool {
	return errors.Is(err, ErrCanceled)
}

func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded)
}

func IsFdUnavailable(err error) bool {
	return errors.Is(err, ErrFdUnavailable)
}

func IsOperationInvalid(err error) bool {
	return errors.Is(err, ErrOpInvalid)
}

func MapErr(err error) error {
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return err
}

type CanceledError struct{}

func (e *CanceledError) Error() string   { return "operation was canceled" }
func (e *CanceledError) Timeout() bool   { return false }
func (e *CanceledError) Temporary() bool { return true }
func (e *CanceledError) Is(err error) bool {
	if errors.Is(err, syscall.ECANCELED) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	return false
}

type TimeoutError struct{}

func (e *TimeoutError) Error() string   { return "i/o timeout" }
func (e *TimeoutError) Timeout() bool   { return true }
func (e *TimeoutError) Temporary() bool { return true }
func (e *TimeoutError) Is(err error) bool {
	return err == context.DeadlineExceeded
}

func NewInvalidOpErr(err error) error {
	return &OperationInvalidError{err}
}

type OperationInvalidError struct {
	Err error
}

func (e *OperationInvalidError) Error() string   { return "invalid operation: " + e.Err.Error() }
func (e *OperationInvalidError) Timeout() bool   { return false }
func (e *OperationInvalidError) Temporary() bool { return false }
func (e *OperationInvalidError) Is(err error) bool {
	return errors.Is(err, ErrOpInvalid)
}
