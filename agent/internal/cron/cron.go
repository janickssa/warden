// Package cron is the agent's half of Warden's schedule cron (DECISIONS M7-01): five fields, evaluated in
// Europe/Copenhagen, with the same rules as backend/src/warden/schedules/cron.py. Both sides run the
// vectors in policy-fixtures/schedule_vectors.json. The agent only needs to know whether a time is a slot.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the agent must not depend on the target's zoneinfo
)

const (
	TZName = "Europe/Copenhagen"
	maxLen = 100
)

var Location = mustLoad()

func mustLoad() *time.Location {
	loc, err := time.LoadLocation(TZName)
	if err != nil {
		panic(err)
	}
	return loc
}

type Cron struct {
	Expr                 string
	minutes, hours, days map[int]bool
	months, weekdays     map[int]bool
	daysAny, weekdaysAny bool
}

type field struct {
	name   string
	lo, hi int
}

var fields = [5]field{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}

func number(text string, f field) (int, error) {
	if text == "" || len(text) > 2 {
		return 0, fmt.Errorf("cron %s: %q isn't a number", f.name, text)
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("cron %s: %q isn't a number", f.name, text)
		}
	}
	n, _ := strconv.Atoi(text)
	if n < f.lo || n > f.hi {
		return 0, fmt.Errorf("cron %s: %d is outside %d–%d", f.name, n, f.lo, f.hi)
	}
	return n, nil
}

func parseField(text string, f field) (map[int]bool, error) {
	if text == "" {
		return nil, fmt.Errorf("cron %s is empty", f.name)
	}
	out := map[int]bool{}
	for _, item := range strings.Split(text, ",") {
		base, stepText, slash := strings.Cut(item, "/")
		step := 1
		if slash {
			s, err := number(stepText, field{f.name, 1, f.hi})
			if err != nil {
				return nil, err
			}
			step = s
		}
		var a, b int
		switch {
		case base == "*":
			a, b = f.lo, f.hi
		case strings.Contains(base, "-"):
			left, right, _ := strings.Cut(base, "-")
			var err error
			if a, err = number(left, f); err != nil {
				return nil, err
			}
			if b, err = number(right, f); err != nil {
				return nil, err
			}
			if a > b {
				return nil, fmt.Errorf("cron %s: range %d-%d runs backwards", f.name, a, b)
			}
		default:
			var err error
			if a, err = number(base, f); err != nil {
				return nil, err
			}
			b = a
			if slash {
				b = f.hi
			}
		}
		for v := a; v <= b; v += step {
			out[v] = true
		}
	}
	return out, nil
}

// Parse refuses anything outside the documented subset.
func Parse(expr string) (*Cron, error) {
	if len(expr) > maxLen {
		return nil, fmt.Errorf("cron must be at most 100 plain characters")
	}
	for _, r := range expr {
		if r > 127 {
			return nil, fmt.Errorf("cron must be at most 100 plain characters")
		}
	}
	parts := strings.Split(expr, " ")
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron needs exactly five fields separated by single spaces")
	}
	var sets [5]map[int]bool
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("cron needs exactly five fields separated by single spaces")
		}
		s, err := parseField(p, fields[i])
		if err != nil {
			return nil, err
		}
		sets[i] = s
	}
	weekdays := map[int]bool{}
	for d := range sets[4] {
		weekdays[d%7] = true
	}
	return &Cron{
		Expr: expr, minutes: sets[0], hours: sets[1], days: sets[2], months: sets[3], weekdays: weekdays,
		daysAny: strings.HasPrefix(parts[2], "*"), weekdaysAny: strings.HasPrefix(parts[4], "*"),
	}, nil
}

func (c *Cron) dayMatches(t time.Time) bool {
	if !c.months[int(t.Month())] {
		return false
	}
	dom, dow := c.days[t.Day()], c.weekdays[int(t.Weekday())]
	if c.daysAny || c.weekdaysAny {
		return dom && dow
	}
	return dom || dow
}

// IsSlot reports whether the instant is a whole minute whose Copenhagen wall time matches, and isn't the
// second occurrence of a wall time repeated when the clocks go back.
func (c *Cron) IsSlot(instant time.Time) bool {
	if instant.Second() != 0 || instant.Nanosecond() != 0 {
		return false
	}
	local := instant.In(Location)
	if !c.minutes[local.Minute()] || !c.hours[local.Hour()] || !c.dayMatches(local) {
		return false
	}
	earlier := instant.Add(-time.Hour).In(Location)
	return wall(earlier) != wall(local)
}

func wall(t time.Time) string { return t.Format("2006-01-02T15:04") }
