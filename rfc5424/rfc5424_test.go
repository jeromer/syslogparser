package rfc5424

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/stretchr/testify/suite"
)

type RFC5424TestSuite struct {
	suite.Suite
}

func (s *RFC5424TestSuite) TestParser() {
	tmpTZ, err := time.Parse("-07:00", "-07:00")
	s.Require().Nil(err)

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
		s.Require().Equal(
			p,
			&Parser{
				buff:   buff,
				cursor: 0,
				l:      len(tc.input),
			},
			tc.description,
		)

		err := p.Parse()
		s.Require().Nil(err)

		obtained := p.Dump()
		for k, v := range obtained {
			s.Require().Equal(
				v, tc.expectedParts[k], tc.description,
			)
		}
	}
}

func (s *RFC5424TestSuite) TestParseHeader() {
	ts := time.Date(2003, time.October, 11, 22, 14, 15, 3*10e5, time.UTC)
	tsString := "2003-10-11T22:14:15.003Z"
	hostname := "mymachine.example.com"
	appName := "su"
	procId := "123"
	msgId := "ID47"
	nilValue := string(NILVALUE)
	headerFmt := "<165>1 %s %s %s %s %s "
	pri := syslogparser.Priority{
		P: 165,
		F: syslogparser.Facility{Value: 20},
		S: syslogparser.Severity{Value: 5},
	}
	testCases := []struct {
		description string
		input       string
		expectedHdr header
	}{
		{
			description: "HEADER complete",
			input:       fmt.Sprintf(headerFmt, tsString, hostname, appName, procId, msgId),
			expectedHdr: header{
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
			expectedHdr: header{
				priority:  pri,
				version:   1,
				timestamp: *new(time.Time),
				hostname:  hostname,
				appName:   appName,
				procId:    procId,
				msgId:     msgId,
			},
		},
		{
			description: "HOSTNAME as NILVALUE",
			input:       fmt.Sprintf(headerFmt, tsString, nilValue, appName, procId, msgId),
			expectedHdr: header{
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
			expectedHdr: header{
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
			expectedHdr: header{
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
			expectedHdr: header{
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

		s.Require().Nil(
			err, tc.description,
		)

		s.Require().Equal(
			obtained, tc.expectedHdr, tc.description,
		)

		s.Require().Equal(
			p.cursor, len(tc.input), tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseTimestamp() {
	tz := "-04:00"
	tmpTZ, err := time.Parse("-07:00", tz)
	s.Require().Nil(err)
	s.Require().NotNil(tmpTZ)

	testCases := []struct {
		description       string
		input             string
		expectedTS        time.Time
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description: "UTC timestamp",
			input:       "1985-04-12T23:20:50.52Z",
			expectedTS: time.Date(
				1985, time.April, 12,
				23, 20, 50, 52*10e6,
				time.UTC,
			),
			expectedCursorPos: 23,
			expectedErr:       nil,
		},
		{
			description: "numeric timezone",
			input:       "1985-04-12T19:20:50.52" + tz,
			expectedTS: time.Date(
				1985, time.April, 12,
				19, 20, 50, 52*10e6,
				tmpTZ.Location(),
			),
			expectedCursorPos: 28,
			expectedErr:       nil,
		},
		{
			description: "timestamp with ms",
			input:       "2003-10-11T22:14:15.003Z",
			expectedTS: time.Date(
				2003, time.October, 11,
				22, 14, 15, 3*10e5,
				time.UTC,
			),
			expectedCursorPos: 24,
			expectedErr:       nil,
		},
		{
			description: "timestamp with us",
			input:       "2003-08-24T05:14:15.000003" + tz,
			expectedTS: time.Date(
				2003, time.August, 24,
				5, 14, 15, 3*10e2,
				tmpTZ.Location(),
			),
			expectedCursorPos: 32,
			expectedErr:       nil,
		},
		{
			description:       "timestamp with ns",
			input:             "2003-08-24T05:14:15.000000003-07:00",
			expectedCursorPos: 26,
			expectedErr:       syslogparser.ErrTimestampUnknownFormat,
		},
		{
			description:       "nil timestamp",
			input:             "-",
			expectedCursorPos: 1,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseTimestamp()

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)

		tfmt := time.RFC3339Nano
		s.Require().Equal(
			obtained.Format(tfmt),
			tc.expectedTS.Format(tfmt),
			tc.description,
		)

		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseYear() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedYear, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseMonth() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedMonth, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseDay() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedDay, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseFullDate() {
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
			expectedErr:       syslogparser.ErrTimestampUnknownFormat,
		},
		{
			description:       "invalid separator 2/2",
			input:             "2013-10+28",
			expectedDate:      fullDate{},
			expectedCursorPos: 7,
			expectedErr:       syslogparser.ErrTimestampUnknownFormat,
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

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			obtained, tc.expectedDate, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseHour() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedHour, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseMinute() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedMinute, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseSecond() {
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
			expectedErr:       syslogparser.ErrEOL,
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

		s.Require().Equal(
			obtained, tc.expectedSecond, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseSecFrac() {
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

		s.Require().Equal(
			obtained, tc.expectedSecFrac, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseNumericalTimeOffset() {
	buff := []byte("+02:00")
	cursor := 0
	l := len(buff)
	tmpTs, err := time.Parse("-07:00", string(buff))
	s.Require().Nil(err)

	obtained, err := parseNumericalTimeOffset(buff, &cursor, l)
	s.Require().Nil(err)

	expected := tmpTs.Location()
	s.Require().Equal(obtained, expected)

	s.Require().Equal(cursor, 6)
}

func (s *RFC5424TestSuite) TestParseTimeOffset() {
	buff := []byte("Z")
	cursor := 0
	l := len(buff)

	obtained, err := parseTimeOffset(buff, &cursor, l)
	s.Require().Nil(err)
	s.Require().Equal(obtained, time.UTC)
	s.Require().Equal(cursor, 1)
}

func (s *RFC5424TestSuite) TestGetHourMin() {
	buff := []byte("12:34")
	cursor := 0
	l := len(buff)

	expectedH := 12
	expectedM := 34

	obtainedH, obtainedM, err := getHourMinute(
		buff, &cursor, l,
	)

	s.Require().Nil(err)
	s.Require().Equal(obtainedH, expectedH)
	s.Require().Equal(obtainedM, expectedM)

	s.Require().Equal(cursor, l)
}

func (s *RFC5424TestSuite) TestParsePartialTime() {
	buff := []byte("05:14:15.000003")
	cursor := 0
	l := len(buff)

	obtained, err := parsePartialTime(
		buff, &cursor, l,
	)

	expected := partialTime{
		hour:    5,
		minute:  14,
		seconds: 15,
		secFrac: 0.000003,
	}

	s.Require().Nil(err)
	s.Require().Equal(obtained, expected)
	s.Require().Equal(cursor, l)
}

func (s *RFC5424TestSuite) TestParseFullTime() {
	tz := "-02:00"
	buff := []byte("05:14:15.000003" + tz)
	cursor := 0
	l := len(buff)

	tmpTs, err := time.Parse("-07:00", string(tz))
	s.Require().Nil(err)

	obtained, err := parseFullTime(
		buff, &cursor, l,
	)

	expected := fullTime{
		pt: partialTime{
			hour:    5,
			minute:  14,
			seconds: 15,
			secFrac: 0.000003,
		},
		loc: tmpTs.Location(),
	}

	s.Require().Nil(err)
	s.Require().Equal(obtained, expected)
	s.Require().Equal(cursor, 21)
}

func (s *RFC5424TestSuite) TestToNSec() {
	testCases := map[float64]int{
		0.52:     520000000,
		0.003:    3000000,
		0.000003: 3000,
	}

	for src, expected := range testCases {
		obtained, err := toNSec(src)
		s.Require().Nil(err)
		s.Require().Equal(obtained, expected)
	}
}

func (s *RFC5424TestSuite) TestParseAppName() {
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

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			obtained, tc.expectedAppName, tc.description,
		)
		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseProcID() {
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

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			obtained, tc.expectedProcID, tc.description,
		)
		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseMsgID() {
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

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			obtained, tc.expectedMsgID, tc.description,
		)
		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)
	}
}

func (s *RFC5424TestSuite) TestParseStructuredData() {
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

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
		s.Require().Equal(
			obtained, tc.expectedData, tc.description,
		)
		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)
	}
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
	buff := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com su 123 ID47")

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

	p := NewParser([]byte(msg))

	for i := 0; i < b.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func TestRFC5424TestSuite(t *testing.T) {
	suite.Run(
		t, new(RFC5424TestSuite),
	)
}
