package logger

import (
	"log/slog"
	"os"
	"strings"
)

// New returns the process logger. The level comes from the PHANTOM_LOG_LEVEL
// environment variable (debug, info, warn, error; default info).
//
// Per-connection destination logging (which host a user visited) is emitted
// at debug level only: at info it wrote every user's browsing history to
// stdout/journald by default, which is both a privacy liability for a proxy
// operator and measurable overhead on busy servers.
func New() *slog.Logger {
	return NewWithLevel(os.Getenv("PHANTOM_LOG_LEVEL"))
}

// NewWithLevel returns a logger at the named level ("" means info).
func NewWithLevel(level string) *slog.Logger {
	return slog.New(
		slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{
				Level: ParseLevel(level),
			},
		),
	)
}

// ParseLevel maps a level name to slog.Level, defaulting to Info.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
