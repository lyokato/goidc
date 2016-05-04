package log

import "fmt"

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
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

	defaultLogger struct {
		colorMap map[LogLevel]TextColor
	}
)

func (level LogLevel) String() string {
	switch level {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "DEBUG"
	case LogLevelFatal:
		return "DEBUG"
	default:
		return ""
	}
}

func NewDefaultLogger() *defaultLogger {
	return &defaultLogger{
		colorMap: map[LogLevel]TextColor{
			LogLevelDebug: White,
			LogLevelInfo:  Green,
			LogLevelWarn:  Blue,
			LogLevelError: Yellow,
			LogLevelFatal: Red,
		},
	}
}

func SetLevelForDefaultLogger(level LogLevel) {
	if level > LogLevelFatal {
		panic("invalid log level")
	}
	defaultLoggerLevel = level
}

func (l *defaultLogger) insertLevelLabel(level LogLevel, msg string) string {
	levelPart := fmt.Sprintf("[%s]", level.String())
	color := l.colorMap[level]
	return fmt.Sprintf("%s %s", paint(levelPart, color), msg)
}

func (l *defaultLogger) Debug(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelDebug {
		msg := l.insertLevelLabel(LogLevelDebug, args[0].(string))
		fmt.Println(msg, args[1:])
	}
}

func (l *defaultLogger) Info(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelInfo {
		msg := l.insertLevelLabel(LogLevelInfo, args[0].(string))
		fmt.Println(msg, args[1:])
	}
}

func (l *defaultLogger) Warn(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelWarn {
		msg := l.insertLevelLabel(LogLevelWarn, args[0].(string))
		fmt.Println(msg, args[1:])
	}
}

func (l *defaultLogger) Error(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelError {
		msg := l.insertLevelLabel(LogLevelError, args[0].(string))
		fmt.Println(msg, args[1:])
	}
}

func (l *defaultLogger) Fatal(args ...interface{}) {
	if defaultLoggerLevel <= LogLevelFatal {
		msg := l.insertLevelLabel(LogLevelFatal, args[0].(string))
		fmt.Println(msg, args[1:])
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
