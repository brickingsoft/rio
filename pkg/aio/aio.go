package aio

import "errors"

var (
	ErrUnexpectedCompletion      = errors.New("aio: unexpected completion error")
	ErrOperationDeadlineExceeded = errors.New("aio: operation deadline exceeded")
	ErrEmptyBytes                = errors.New("aio: empty bytes")
)

func IsUnexpectedCompletionError(err error) bool {
	return errors.Is(err, ErrUnexpectedCompletion)
}
