package io

import "time"

type TimeBuilder func() time.Time

func NowBuilder() TimeBuilder {
	return func() time.Time {
		return time.Now()
	}
}

func FixedTimeBuilder(t time.Time) TimeBuilder {
	return func() time.Time {
		return t
	}
}

func FixedUnixTimeBuilder(sec int64) TimeBuilder {
	return func() time.Time {
		return time.Unix(sec, 0)
	}
}
