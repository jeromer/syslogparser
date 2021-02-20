package rfc5424

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/parsercommon"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	tmpTZ, err := time.Parse("-07:00", "-07:00")
	require.Nil(t, err)

	testCases := []struct {
		description   string
		input         string
		expectedParts syslogparser.LogParts
	}{
		{
			description: "no STRUCTURED-DATA 1/2",
			input:       "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8",
			expectedParts: syslogparser.LogParts{
				"priority": 34,
				"facility": 4,
				"severity": 2,
				"version":  1,
				"timestamp": time.Date(
					2003, time.October, 11,
					22, 14, 15, 3*10e5,
					time.UTC,
				),
				"hostname":        "mymachine.example.com",
				"app_name":        "su",
				"proc_id":         "-",
				"msg_id":          "ID47",
				"structured_data": "-",
				"message":         "'su root' failed for lonvick on /dev/pts/8",
			},
		},
		{
			description: "no STRUCTURED_DATA 2/2",
			input:       "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
			expectedParts: syslogparser.LogParts{
				"priority": 165,
				"facility": 20,
				"severity": 5,
				"version":  1,
				"timestamp": time.Date(
					2003, time.August, 24,
					5, 14, 15, 3*10e2,
					tmpTZ.Location(),
				),
				"hostname":        "192.0.2.1",
				"app_name":        "myproc",
				"proc_id":         "8710",
				"msg_id":          "-",
				"structured_data": "-",
				"message":         "%% It's time to make the do-nuts.",
			},
		},
		{
			description: "with STRUCTURED_DATA",
			input:       `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry...`,
			expectedParts: syslogparser.LogParts{
				"priority": 165,
				"facility": 20,
				"severity": 5,
				"version":  1,
				"timestamp": time.Date(
					2003, time.October, 11,
					22, 14, 15, 3*10e5,
					time.UTC,
				),
				"hostname":        "mymachine.example.com",
				"app_name":        "evntslog",
				"proc_id":         "-",
				"msg_id":          "ID47",
				"structured_data": `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`,
				"message":         "An application event log entry...",
			},
		},
		{
			description: "STRUCTURED_DATA only",
			input:       `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`,
			expectedParts: syslogparser.LogParts{
				"priority": 165,
				"facility": 20,
				"severity": 5,
				"version":  1,
				"timestamp": time.Date(
					2003, time.October, 11,
					22, 14, 15, 3*10e5,
					time.UTC,
				),
				"hostname":        "mymachine.example.com",
				"app_name":        "evntslog",
				"proc_id":         "-",
				"msg_id":          "ID47",
				"structured_data": `[exampleSDID@32473 iut="3" eventSource= "Application" eventID="1011"][examplePriority@32473 class="high"]`,
				"message":         "",
			},
		},
	}

	for _, tc := range testCases {
		buff := []byte(tc.input)

		p := NewParser(buff)
		require.Equal(
			t,
			&Parser{
				buff:   buff,
				cursor: 0,
				l:      len(tc.input),
			},
			p,
			tc.description,
		)

		err := p.Parse()
		require.Nil(t, err)

		obtained := p.Dump()
		for k, v := range obtained {
			require.Equal(
				t, tc.expectedParts[k], v, tc.description,
			)
		}
	}
}

func TestParseHeader(t *testing.T) {
	ts := time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC)
	tsString := "2003-10-11T22:14:15.003Z"
	hostname := "mymachine.example.com"
	appName := "su"
	procId := "123"
	msgId := "ID47"
	nilValue := string(NILVALUE)
	headerFmt := "<165>1 %s %s %s %s %s "
	pri := &parsercommon.Priority{
		P: 165,
		F: parsercommon.Facility{Value: 20},
		S: parsercommon.Severity{Value: 5},
	}
	testCases := []struct {
		description string
		input       string
		expectedHdr *header
	}{
		{
			description: "HEADER complete",
			input:       fmt.Sprintf(headerFmt, tsString, hostname, appName, procId, msgId),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: ts,
				hostname:  hostname,
				appName:   appName,
				procId:    procId,
				msgId:     msgId,
			},
		},
		{
			description: "TIMESTAMP as NILVALUE",
			input:       fmt.Sprintf(headerFmt, nilValue, hostname, appName, procId, msgId),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: time.Time{},
				hostname:  hostname,
				appName:   appName,
				procId:    procId,
				msgId:     msgId,
			},
		},
		{
			description: "HOSTNAME as NILVALUE",
			input:       fmt.Sprintf(headerFmt, tsString, nilValue, appName, procId, msgId),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: ts,
				hostname:  nilValue,
				appName:   appName,
				procId:    procId,
				msgId:     msgId,
			},
		},
		{
			description: "APP-NAME as NILVALUE",
			input:       fmt.Sprintf(headerFmt, tsString, hostname, nilValue, procId, msgId),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: ts,
				hostname:  hostname,
				appName:   nilValue,
				procId:    procId,
				msgId:     msgId,
			},
		},
		{
			description: "PROCID as NILVALUE",
			input:       fmt.Sprintf(headerFmt, tsString, hostname, appName, nilValue, msgId),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: ts,
				hostname:  hostname,
				appName:   appName,
				procId:    nilValue,
				msgId:     msgId,
			},
		},
		{
			description: "MSGID as NILVALUE",
			input:       fmt.Sprintf(headerFmt, tsString, hostname, appName, procId, nilValue),
			expectedHdr: &header{
				priority:  pri,
				version:   1,
				timestamp: ts,
				hostname:  hostname,
				appName:   appName,
				procId:    procId,
				msgId:     nilValue,
			},
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseHeader()

		require.Nil(
			t, err, tc.description,
		)

		require.Equal(
			t, tc.expectedHdr, obtained, tc.description,
		)

		require.Equal(
			t, len(tc.input), p.cursor, tc.description,
		)
	}
}

func TestParseTimestamp(t *testing.T) {
	tz := "-04:00"
	tmpTZ, err := time.Parse("-07:00", tz)
	require.Nil(t, err)
	require.NotNil(t, tmpTZ)

	dt1 := time.Date(
		1985, time.April, 12,
		23, 20, 50, 52*10e6,
		time.UTC,
	)

	dt2 := time.Date(
		1985, time.April, 12,
		19, 20, 50, 52*10e6,
		tmpTZ.Location(),
	)

	dt3 := time.Date(
		2003, time.October, 11,
		22, 14, 15, 3*10e5,
		time.UTC,
	)

	dt4 := time.Date(
		2003, time.August, 24,
		5, 14, 15, 3*10e2,
		tmpTZ.Location(),
	)
	testCases := []struct {
		description       string
		input             string
		expectedTS        *time.Time
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "UTC timestamp",
			input:             "1985-04-12T23:20:50.52Z",
			expectedTS:        &dt1,
			expectedCursorPos: 23,
			expectedErr:       nil,
		},
		{
			description:       "numeric timezone",
			input:             "1985-04-12T19:20:50.52" + tz,
			expectedTS:        &dt2,
			expectedCursorPos: 28,
			expectedErr:       nil,
		},
		{
			description:       "timestamp with ms",
			input:             "2003-10-11T22:14:15.003Z",
			expectedTS:        &dt3,
			expectedCursorPos: 24,
			expectedErr:       nil,
		},
		{
			description:       "timestamp with us",
			input:             "2003-08-24T05:14:15.000003" + tz,
			expectedTS:        &dt4,
			expectedCursorPos: 32,
			expectedErr:       nil,
		},
		{
			description:       "timestamp with ns",
			input:             "2003-08-24T05:14:15.000000003-07:00",
			expectedCursorPos: 26,
			expectedTS:        nil,
			expectedErr:       parsercommon.ErrTimestampUnknownFormat,
		},
		{
			description:       "nil timestamp",
			input:             "-",
			expectedCursorPos: 1,
			expectedTS:        nil,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseTimestamp()

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t,
			tc.expectedCursorPos,
			p.cursor,
			tc.description,
		)

		if tc.expectedErr != nil {
			require.Nil(
				t, obtained, tc.description,
			)

			continue
		}

		if tc.description == "nil timestamp" {
			continue
		}

		tfmt := time.RFC3339Nano
		require.Equal(
			t,
			tc.expectedTS.Format(tfmt),
			obtained.Format(tfmt),
			tc.description,
		)
	}
}

func TestParseYear(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedYear      int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid year",
			input:             "1a2b",
			expectedYear:      0,
			expectedCursorPos: 4,
			expectedErr:       ErrYearInvalid,
		},
		{
			description:       "year too short",
			input:             "123",
			expectedYear:      0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "valid",
			input:             "2013",
			expectedYear:      2013,
			expectedCursorPos: 4,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseYear(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedYear, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseMonth(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedMonth     int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid string",
			input:             "ab",
			expectedMonth:     0,
			expectedCursorPos: 2,
			expectedErr:       ErrMonthInvalid,
		},
		{
			description:       "invalid range 1/2",
			input:             "00",
			expectedMonth:     0,
			expectedCursorPos: 2,
			expectedErr:       ErrMonthInvalid,
		},
		{
			description:       "invalid range 2/2",
			input:             "13",
			expectedMonth:     0,
			expectedCursorPos: 2,
			expectedErr:       ErrMonthInvalid,
		},
		{
			description:       "too short",
			input:             "1",
			expectedMonth:     0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "valid",
			input:             "02",
			expectedMonth:     2,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseMonth(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedMonth, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseDay(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedDay       int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid string",
			input:             "ab",
			expectedDay:       0,
			expectedCursorPos: 2,
			expectedErr:       ErrDayInvalid,
		},
		{
			description:       "too short",
			input:             "1",
			expectedDay:       0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "invalid range 1/2",
			input:             "00",
			expectedDay:       0,
			expectedCursorPos: 2,
			expectedErr:       ErrDayInvalid,
		},
		{
			description:       "invalid range 2/2",
			input:             "32",
			expectedDay:       0,
			expectedCursorPos: 2,
			expectedErr:       ErrDayInvalid,
		},
		{
			description:       "valid",
			input:             "02",
			expectedDay:       2,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseDay(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedDay, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseFullDate(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedDate      fullDate
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid separator 1/2",
			input:             "2013+10-28",
			expectedDate:      fullDate{},
			expectedCursorPos: 4,
			expectedErr:       parsercommon.ErrTimestampUnknownFormat,
		},
		{
			description:       "invalid separator 2/2",
			input:             "2013-10+28",
			expectedDate:      fullDate{},
			expectedCursorPos: 7,
			expectedErr:       parsercommon.ErrTimestampUnknownFormat,
		},
		{
			description:       "valid",
			input:             "2013-10-28",
			expectedDate:      fullDate{2013, 10, 28},
			expectedCursorPos: 10,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseFullDate(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedDate, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseHour(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedHour      int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             "azer",
			expectedHour:      0,
			expectedCursorPos: 2,
			expectedErr:       ErrHourInvalid,
		},
		{
			description:       "too short",
			input:             "1",
			expectedHour:      0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "invalid range 1/2",
			input:             "-1",
			expectedHour:      0,
			expectedCursorPos: 2,
			expectedErr:       ErrHourInvalid,
		},
		{
			description:       "invalid range 2/2",
			input:             "24",
			expectedHour:      0,
			expectedCursorPos: 2,
			expectedErr:       ErrHourInvalid,
		},
		{
			description:       "valid",
			input:             "12",
			expectedHour:      12,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseHour(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedHour, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseMinute(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedMinute    int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             "azer",
			expectedMinute:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrMinuteInvalid,
		},
		{
			description:       "too short",
			input:             "1",
			expectedMinute:    0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "invalid range 1/2",
			input:             "-1",
			expectedMinute:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrMinuteInvalid,
		},
		{
			description:       "invalid range 2/2",
			input:             "60",
			expectedMinute:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrMinuteInvalid,
		},
		{
			description:       "valid",
			input:             "12",
			expectedMinute:    12,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseMinute(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedMinute, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseSecond(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedSecond    int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             "azer",
			expectedSecond:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrSecondInvalid,
		},
		{
			description:       "too short",
			input:             "1",
			expectedSecond:    0,
			expectedCursorPos: 0,
			expectedErr:       parsercommon.ErrEOL,
		},
		{
			description:       "invalid range 1/2",
			input:             "-1",
			expectedSecond:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrSecondInvalid,
		},
		{
			description:       "invalid range 2/2",
			input:             "60",
			expectedSecond:    0,
			expectedCursorPos: 2,
			expectedErr:       ErrSecondInvalid,
		},
		{
			description:       "valid",
			input:             "12",
			expectedSecond:    12,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseSecond(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedSecond, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseSecFrac(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedSecFrac   float64
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             "azerty",
			expectedSecFrac:   0,
			expectedCursorPos: 0,
			expectedErr:       ErrSecFracInvalid,
		},
		{
			description:       "nanoseconds",
			input:             "123456789",
			expectedSecFrac:   0.123456,
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
		{
			description:       "valid 1/4",
			input:             "0",
			expectedSecFrac:   0,
			expectedCursorPos: 1,
			expectedErr:       nil,
		},
		{
			description:       "valid 2/4",
			input:             "52",
			expectedSecFrac:   0.52,
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
		{
			description:       "valid 3/4",
			input:             "003",
			expectedSecFrac:   0.003,
			expectedCursorPos: 3,
			expectedErr:       nil,
		},
		{
			description:       "valid 4/4",
			input:             "000003",
			expectedSecFrac:   0.000003,
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseSecFrac(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedSecFrac, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseNumericalTimeOffset(t *testing.T) {
	buff := []byte("+02:00")
	cursor := 0
	l := len(buff)

	tmpTs, err := time.Parse("-07:00", string(buff))
	require.Nil(t, err)

	obtained, err := parseNumericalTimeOffset(
		buff, &cursor, l,
	)

	require.Nil(t, err)

	expected := tmpTs.Location()
	require.Equal(t, expected, obtained)
	require.Equal(t, 6, cursor)
}

func TestParseTimeOffset(t *testing.T) {
	buff := []byte("Z")
	cursor := 0
	l := len(buff)

	obtained, err := parseTimeOffset(
		buff, &cursor, l,
	)

	require.Nil(t, err)
	require.Equal(t, time.UTC, obtained)
	require.Equal(t, 1, cursor)
}

func TestGetHourMin(t *testing.T) {
	buff := []byte("12:34")
	cursor := 0
	l := len(buff)

	expectedH := 12
	expectedM := 34

	obtainedH, obtainedM, err := getHourMinute(
		buff, &cursor, l,
	)

	require.Nil(t, err)
	require.Equal(t, expectedH, obtainedH)
	require.Equal(t, expectedM, obtainedM)
	require.Equal(t, l, cursor)
}

func TestParsePartialTime(t *testing.T) {
	buff := []byte("05:14:15.000003")
	cursor := 0
	l := len(buff)

	obtained, err := parsePartialTime(
		buff, &cursor, l,
	)

	expected := &partialTime{
		hour:    5,
		minute:  14,
		seconds: 15,
		secFrac: 0.000003,
	}

	require.Nil(t, err)
	require.Equal(t, expected, obtained)
	require.Equal(t, l, cursor)
}

func TestParseFullTime(t *testing.T) {
	tz := "-02:00"
	buff := []byte("05:14:15.000003" + tz)
	cursor := 0
	l := len(buff)

	tmpTs, err := time.Parse("-07:00", string(tz))
	require.Nil(t, err)

	obtained, err := parseFullTime(
		buff, &cursor, l,
	)

	expected := &fullTime{
		pt: &partialTime{
			hour:    5,
			minute:  14,
			seconds: 15,
			secFrac: 0.000003,
		},
		loc: tmpTs.Location(),
	}

	require.Nil(t, err)
	require.Equal(t, expected, obtained)
	require.Equal(t, 21, cursor)
}

func TestToNSec(t *testing.T) {
	testCases := map[float64]int{
		0.52:     520000000,
		0.003:    3000000,
		0.000003: 3000,
	}

	for src, expected := range testCases {
		obtained, err := toNSec(src)
		require.Nil(t, err)
		require.Equal(t, expected, obtained)
	}
}

func TestParseAppName(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedAppName   string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "valid",
			input:             "su ",
			expectedAppName:   "su",
			expectedCursorPos: 2,
			expectedErr:       nil,
		},
		{
			description:       "too long",
			input:             "suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu ",
			expectedAppName:   "",
			expectedCursorPos: 48,
			expectedErr:       ErrInvalidAppName,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseAppName()

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedAppName, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)
	}
}

func TestParseProcID(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedProcID    string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "valid",
			input:             "123foo ",
			expectedProcID:    "123foo",
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
		{
			description:       "too long",
			input:             strings.Repeat("a", 129),
			expectedProcID:    "",
			expectedCursorPos: 128,
			expectedErr:       ErrInvalidProcId,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseProcId()

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedProcID, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)
	}
}

func TestParseMsgID(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedMsgID     string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "valid",
			input:             "123foo ",
			expectedMsgID:     "123foo",
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
		{
			description:       "too long",
			input:             strings.Repeat("a", 33),
			expectedMsgID:     "",
			expectedCursorPos: 32,
			expectedErr:       ErrInvalidMsgId,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseMsgId()

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedMsgID, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)
	}
}

func TestParseStructuredData(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedData      string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "nil",
			input:             "-",
			expectedData:      "-",
			expectedCursorPos: 1,
			expectedErr:       nil,
		},
		{
			description:       "single",
			input:             `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"]`,
			expectedData:      `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"]`,
			expectedCursorPos: 67,
			expectedErr:       nil,
		},
		{
			description:       "multiple",
			input:             `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"][examplePriority@32473 class="high"]`,
			expectedData:      `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"][examplePriority@32473 class="high"]`,
			expectedCursorPos: 103,
			expectedErr:       nil,
		},
		{
			description:       "multiple invalid",
			input:             `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"] [examplePriority@32473 class="high"]`,
			expectedData:      `[exampleSDID@32473 iut="3" eventSource="Application"eventID="1011"]`,
			expectedCursorPos: 67,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0
		obtained, err := parseStructuredData(
			[]byte(tc.input),
			&cursor,
			len(tc.input),
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedData, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)
	}
}

func TestParseMessageSizeChecks(t *testing.T) {
	start := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] `
	msg := start + strings.Repeat("a", MAX_PACKET_LEN)

	p := NewParser([]byte(msg))
	err := p.Parse()
	fields := p.Dump()

	require.Nil(
		t, err,
	)

	require.Len(
		t,
		fields["message"],
		MAX_PACKET_LEN-len(start),
	)

	// ---

	msg = start + " hello "
	p = NewParser([]byte(msg))
	err = p.Parse()
	fields = p.Dump()

	require.Nil(t, err)
	require.Equal(t, "hello", fields["message"])
}

func BenchmarkParseTimestamp(b *testing.B) {
	buff := []byte("2003-08-24T05:14:15.000003-07:00")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTimestamp()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHeader(b *testing.B) {
	buff := []byte(
		"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su 123 ID47 ",
	)

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseFull(b *testing.B) {
	msg := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry...`

	for i := 0; i < b.N; i++ {
		p := NewParser(
			[]byte(msg),
		)

		err := p.Parse()
		if err != nil {
			panic(err)
		}
	}
}
