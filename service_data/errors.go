package service_data

type ErrorType int

const (
	ErrUnsupported ErrorType = iota
	ErrServerError
	ErrNotFound
	ErrConditionMismatch
)

type Error struct {
	typ ErrorType
}

func NewError(typ ErrorType) *Error {
	return &Error{typ}
}

func (e *Error) Type() ErrorType {
	return e.typ
}
