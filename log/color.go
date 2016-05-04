package log

import "fmt"

type TextColor int

const (
	Black TextColor = 30 + iota
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

const escape = "\x1b"

func paint(txt string, color TextColor) string {
	return fmt.Sprintf("%s[%dm%s%s[m", escape, color, txt, escape)
}
