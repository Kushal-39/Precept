package cmd

// ExitError carries a process exit code from command logic to main.
// Commands stay testable by returning it instead of calling os.Exit,
// and main maps it to the final process status.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

// Silent reports whether the error carries no message to print.
func (e *ExitError) Silent() bool { return e.Message == "" }
