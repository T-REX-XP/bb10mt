// Package apperror defines stable process exit codes for automation and users.
package apperror

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
)

const (
	Usage        = 2
	Input        = 3
	OutputExists = 4
	Validation   = 5
	Space        = 6
	Tool         = 7
	Verification = 8
	IO           = 9
	Version      = 10
)

type Error struct {
	Code                int
	Name, Message, Hint string
	Cause               error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func New(code int, message, hint string) *Error {
	e := ClassifyCode(code)
	e.Message, e.Hint = message, hint
	return e
}

func ClassifyCode(code int) *Error {
	names := map[int]string{Usage: "USAGE", Input: "INPUT_INVALID", OutputExists: "OUTPUT_EXISTS", Validation: "VALIDATION_FAILED", Space: "DISK_SPACE", Tool: "TOOL_FAILED", Verification: "VERIFICATION_FAILED", IO: "IO_FAILED", Version: "VERSION_FAILED", 130: "INTERRUPTED"}
	name := names[code]
	if name == "" {
		code, name = IO, "IO_FAILED"
	}
	return &Error{Code: code, Name: name}
}

func Classify(err error) *Error {
	var typed *Error
	if errors.As(err, &typed) {
		return typed
	}
	code, hint := Validation, "Check the input format/content and the reported details."
	switch {
	case errors.Is(err, os.ErrNotExist):
		code, hint = Input, "Check that the input path exists and is readable."
	case errors.Is(err, os.ErrExist):
		code, hint = OutputExists, "Choose a NEW output path; existing files and folders are preserved."
	case errors.Is(err, syscall.ENOSPC) || (runtime.GOOS == "windows" &&
		(errors.Is(err, syscall.Errno(112)) || errors.Is(err, syscall.Errno(39)))):
		code, hint = Space, "Free space or choose an output/temp directory on another volume."
	case errors.Is(err, os.ErrPermission):
		code, hint = IO, "Check access permissions for the reported path."
	default:
		var path *os.PathError
		if errors.As(err, &path) {
			code, hint = IO, "Check the reported path and filesystem access."
		}
	}
	e := New(code, err.Error(), hint)
	e.Cause = err
	return e
}

func Print(w io.Writer, err error) int {
	e := Classify(err)
	fmt.Fprintf(w, "ERROR [%s:%d] %s\n", e.Name, e.Code, e.Message)
	if e.Hint != "" {
		fmt.Fprintln(w, "Hint:", e.Hint)
	}
	return e.Code
}
