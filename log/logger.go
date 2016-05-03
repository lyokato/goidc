package log

import "fmt"

const (
	LogLevelDebug = 0
	LogLevelInfo  = 1
	LogLevelWarn  = 2
	LogLevelError = 3
	LogLevelFatal = 4
)

var defaultLoggerLevel = LogLevelDebug

type (
	Logger interface {
		Debug(args ...interface{})
		Info(args ...interface{})
		Warn(args ...interface{})
		Error(args ...interface{})
		Fatal(args ...interface{})
		Debugf(format string, args ...interface{})
		Infof(format string, args ...interface{})
		Warnf(format string, args ...interface{})
		Errorf(format string, args ...interface{})
		Fatalf(format string, args ...interface{})
	}

	defaultLogger struct{}
)

func NewDefaultLogger() *defaultLogger {
	return &defaultLogger{}
}

func SetLevelForDefaultLogger(level int) {
	if level > LogLevelFatal {
		panic("invalid log level")
	}
	defaultLoggerLevel = level
}

func (l *defaultLogger) Debug(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelDebug {
		fmt.Println(args...)
	}
}

func (l *defaultLogger) Info(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelInfo {
		fmt.Println(args...)
	}
}

func (l *defaultLogger) Warn(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelWarn {
		fmt.Println(args...)
	}
}

func (l *defaultLogger) Error(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelError {
		fmt.Println(args...)
	}
}

func (l *defaultLogger) Fatal(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelFatal {
		fmt.Println(args...)
	}
}

func (l *defaultLogger) Debugf(format string, args ...interface{}) {
	if defaultLoggerLevel <= LogLevelDebug {
		fmt.Println(fmt.Sprintf(format, args...))
	}
}

func (l *defaultLogger) Infof(format string, args ...interface{}) {
	if defaultLoggerLevel <= LogLevelInfo {
		fmt.Println(fmt.Sprintf(format, args...))
	}
}

func (l *defaultLogger) Warnf(format string, args ...interface{}) {
	if defaultLoggerLevel <= LogLevelWarn {
		fmt.Println(fmt.Sprintf(format, args...))
	}
}

func (l *defaultLogger) Errorf(format string, args ...interface{}) {
	if defaultLoggerLevel <= LogLevelError {
		fmt.Println(fmt.Sprintf(format, args...))
	}
}

func (l *defaultLogger) Fatalf(format string, args ...interface{}) {
	if defaultLoggerLevel <= LogLevelFatal {
		fmt.Println(fmt.Sprintf(format, args...))
	}
}
