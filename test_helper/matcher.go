package test_helper

import (
	"fmt"
	"reflect"
	"regexp"
)

type (
	Matcher interface {
		Match(v interface{}) bool
		WantValue() string
	}
	Int64Matcher struct {
		value int64
	}
	Int64RangeMatcher struct {
		from int64
		to   int64
	}
	StrMatcher struct {
		value string
	}
	RegexMatcher struct {
		origin string
		value  *regexp.Regexp
	}
)

func NewInt64Matcher(v int64) *Int64Matcher {
	return &Int64Matcher{v}
}

func NewInt64RangeMatcher(from, to int64) *Int64RangeMatcher {
	return &Int64RangeMatcher{from, to}
}

func (m *Int64Matcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Float64 {
		return false
	}
	int_value := int64(v.(float64))
	return m.value == int_value
}

func (m *Int64Matcher) WantValue() string {
	return fmt.Sprintf("%d", m.value)
}

func (m *Int64RangeMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.Float64 {
		return false
	}
	int_value := int64(v.(float64))
	return m.from <= int_value && m.to >= int_value
}

func (m *Int64RangeMatcher) WantValue() string {
	return fmt.Sprintf("%d ~ %d", m.from, m.to)
}

func NewStrMatcher(v string) *StrMatcher {
	return &StrMatcher{v}
}

func (m *StrMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.String {
		return false
	}
	str, _ := v.(string)
	return m.value == str
}

func (m *StrMatcher) WantValue() string {
	return m.value
}

func NewRegexMatcher(v string) *RegexMatcher {
	return &RegexMatcher{v, regexp.MustCompile(v)}
}

func (m *RegexMatcher) Match(v interface{}) bool {
	value := reflect.ValueOf(v)
	if value.Kind() != reflect.String {
		return false
	}
	str, _ := v.(string)
	return m.value.MatchString(str)
}

func (m *RegexMatcher) WantValue() string {
	return m.origin
}
