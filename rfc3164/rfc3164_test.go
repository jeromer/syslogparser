package rfc3164

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/parsercommon"
	"github.com/stretchr/testify/require"
)

var (
	// XXX : corresponds to the length of the last tried timestamp format
	// XXX : Jan  2 15:04:05
	lastTriedTimestampLen = 15
)

func TestParser_Valid(t *testing.T) {
	buff := []byte(
		"<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
	)

	p := NewParser(buff)

	require.Equal(
		t,
		&Parser{
			buff:     buff,
			cursor:   0,
			l:        len(buff),
			location: time.UTC,
		},
		p,
	)

	err := p.Parse()

	require.Nil(
		t, err,
	)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.October,
				11, 22, 14, 15, 0,
				time.UTC,
			),
			"hostname": "mymachine",
			"tag":      "very.large.syslog.message.tag",
			"content":  "'su root' failed for lonvick on /dev/pts/8",
			"priority": 34,
			"facility": 4,
			"severity": 2,
		},
		p.Dump(),
	)
}

func TestParser_WithPriority(t *testing.T) {
	buff := []byte(
		"Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
	)

	pri := parsercommon.NewPriority(0)

	p := NewParser(buff)
	p.WithPriority(pri)

	require.Equal(
		t,
		&Parser{
			buff:     buff,
			cursor:   0,
			l:        len(buff),
			location: time.UTC,
			priority: pri,
		},
		p,
	)

	err := p.Parse()

	require.Nil(
		t, err,
	)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.October,
				11, 22, 14, 15, 0,
				time.UTC,
			),
			"hostname": "mymachine",
			"tag":      "very.large.syslog.message.tag",
			"content":  "'su root' failed for lonvick on /dev/pts/8",
			"priority": 0,
			"facility": 0,
			"severity": 0,
		},
		p.Dump(),
	)
}

func TestParser_WithHostname(t *testing.T) {
	buff := []byte(
		"<30>Jun 23 13:17:42 chronyd[1119]: Selected source 192.168.65.1",
	)

	p := NewParser(buff)
	p.WithHostname("dummy")

	err := p.Parse()
	require.Nil(t, err)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.June,
				23, 13, 17, 42, 0,
				time.UTC,
			),
			"hostname": "dummy",
			"tag":      "chronyd",
			"content":  "Selected source 192.168.65.1",
			"priority": 30,
			"facility": 3,
			"severity": 6,
		},
		p.Dump(),
	)
}

func TestParser_WithTag(t *testing.T) {
	buff := []byte(
		"<30>Jun 23 13:17:42 localhost Selected source 192.168.65.1",
	)

	tag := "chronyd"
	p := NewParser(buff)
	p.WithTag(tag)

	err := p.Parse()
	require.Nil(t, err)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.June,
				23, 13, 17, 42, 0,
				time.UTC,
			),
			"hostname": "localhost",
			"tag":      "chronyd",
			"content":  "Selected source 192.168.65.1",
			"priority": 30,
			"facility": 3,
			"severity": 6,
		},
		p.Dump(),
	)
}

func TestParser_WithLocation(t *testing.T) {
	buff := []byte(
		"<30>Jun 23 13:17:42 localhost foo: Selected source 192.168.65.1",
	)

	loc, err := time.LoadLocation("America/New_York")
	require.Nil(t, err)

	p := NewParser(buff)
	p.WithLocation(loc)

	err = p.Parse()
	require.Nil(t, err)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.June,
				23, 13, 17, 42, 0,
				loc,
			),
			"hostname": "localhost",
			"tag":      "foo",
			"content":  "Selected source 192.168.65.1",
			"priority": 30,
			"facility": 3,
			"severity": 6,
		},
		p.Dump(),
	)
}

func TestParser_WithPriorityHostnameTag(t *testing.T) {
	buff := []byte(
		"Oct 11 22:14:15 'su root' failed for lonvick on /dev/pts/8",
	)

	pri := parsercommon.NewPriority(0)
	h := "mymachine"
	tag := "foo"

	p := NewParser(buff)
	p.WithPriority(pri)
	p.WithHostname(h)
	p.WithTag(tag)

	require.Equal(
		t,
		&Parser{
			buff:     buff,
			cursor:   0,
			l:        len(buff),
			location: time.UTC,
			priority: pri,
			hostname: h,
			tmpTag:   tag,
		},
		p,
	)

	err := p.Parse()

	require.Nil(
		t, err,
	)

	require.Equal(
		t,
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.October,
				11, 22, 14, 15, 0,
				time.UTC,
			),
			"hostname": h,
			"tag":      tag,
			"content":  "'su root' failed for lonvick on /dev/pts/8",
			"priority": 0,
			"facility": 0,
			"severity": 0,
		},
		p.Dump(),
	)
}

func TestParseHeader(t *testing.T) {
	date := time.Date(
		time.Now().Year(),
		time.October,
		11, 22, 14, 15, 0,
		time.UTC,
	)

	testCases := []struct {
		description       string
		input             string
		expectedHdr       *header
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description: "valid headers",
			input:       "Oct 11 22:14:15 mymachine ",
			expectedHdr: &header{
				hostname:  "mymachine",
				timestamp: date,
			},
			expectedCursorPos: 25,
			expectedErr:       nil,
		},
		{
			description: "valid headers with prepended space",
			input:       " Oct 11 22:14:15 mymachine ",
			expectedHdr: &header{
				hostname:  "mymachine",
				timestamp: date,
			},
			expectedCursorPos: 26,
			expectedErr:       nil,
		},
		{
			description:       "invalid timestamp",
			input:             "Oct 34 32:72:82 mymachine ",
			expectedHdr:       nil,
			expectedCursorPos: lastTriedTimestampLen + 1,
			expectedErr:       parsercommon.ErrTimestampUnknownFormat,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseHeader()

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)

		require.Equal(
			t, tc.expectedHdr, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)
	}
}

func TestParsemessage_Valid(t *testing.T) {
	content := "foo bar baz blah quux"

	buff := []byte("sometag[123]: " + content)

	msg := &message{
		tag:     "sometag",
		content: content,
	}

	p := NewParser(buff)
	obtained, err := p.parsemessage()

	require.Equal(
		t, parsercommon.ErrEOL, err,
	)

	require.Equal(
		t, msg, obtained,
	)

	require.Equal(
		t, len(buff), p.cursor,
	)
}

func TestParseTimestamp(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedTS        time.Time
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             "Oct 34 32:72:82",
			expectedCursorPos: lastTriedTimestampLen,
			expectedErr:       parsercommon.ErrTimestampUnknownFormat,
		},
		{
			description: "trailing space",
			input:       "Oct 11 22:14:15 ",
			expectedTS: time.Date(
				time.Now().Year(),
				time.October,
				11, 22, 14, 15, 0,
				time.UTC,
			),
			expectedCursorPos: 16,
			expectedErr:       nil,
		},
		{
			description: "one digit for month",
			input:       "Oct  1 22:14:15",
			expectedTS: time.Date(
				time.Now().Year(),
				time.October,
				1, 22, 14, 15, 0,
				time.UTC,
			),
			expectedCursorPos: 15,
			expectedErr:       nil,
		},
		{
			description: "valid timestamp",
			input:       "Oct 11 22:14:15",
			expectedTS: time.Date(
				time.Now().Year(),
				time.October,
				11, 22, 14, 15, 0,
				time.UTC,
			),
			expectedCursorPos: 15,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseTimestamp()

		require.Equal(
			t, tc.expectedTS, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)
	}
}

func TestParseTag(t *testing.T) {
	testCases := []struct {
		description       string
		input             string
		expectedTag       string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "with pid",
			input:             "apache2[10]:",
			expectedTag:       "apache2",
			expectedCursorPos: 12,
			expectedErr:       nil,
		},
		{
			description:       "without pid",
			input:             "apache2:",
			expectedTag:       "apache2",
			expectedCursorPos: 8,
			expectedErr:       nil,
		},
		{
			description:       "trailing space",
			input:             "apache2: ",
			expectedTag:       "apache2",
			expectedCursorPos: 9,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		p := NewParser([]byte(tc.input))
		obtained, err := p.parseTag()

		require.Equal(
			t, obtained, tc.expectedTag, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, p.cursor, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)
	}
}

func TestParseContent_Valid(t *testing.T) {
	buff := []byte(" foo bar baz quux ")
	content := string(bytes.Trim(buff, " "))

	p := NewParser(buff)
	obtained, err := p.parseContent()

	require.Equal(
		t, err, parsercommon.ErrEOL,
	)

	require.Equal(
		t, content, obtained,
	)

	require.Equal(
		t, len(content), p.cursor,
	)
}

func TestParseMessageSizeChecks(t *testing.T) {
	start := "<34>Oct 11 22:14:15 mymachine su: "
	msg := start + strings.Repeat("a", MAX_PACKET_LEN)

	p := NewParser([]byte(msg))
	err := p.Parse()
	fields := p.Dump()

	require.Nil(
		t, err,
	)

	require.Len(
		t,
		fields["content"],
		MAX_PACKET_LEN-len(start),
	)

	// ---

	msg = start + "hello"
	p = NewParser([]byte(msg))
	err = p.Parse()
	fields = p.Dump()

	require.Nil(
		t, err,
	)

	require.Equal(
		t, "hello", fields["content"],
	)
}

func BenchmarkParseTimestamp(b *testing.B) {
	buff := []byte("Oct 11 22:14:15")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTimestamp()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHostname(b *testing.B) {
	buff := []byte("gimli.local")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHostname()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseTag(b *testing.B) {
	buff := []byte("apache2[10]:")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseTag()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseHeader(b *testing.B) {
	buff := []byte("Oct 11 22:14:15 mymachine ")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parseHeader()
		if err != nil {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParsemessage(b *testing.B) {
	buff := []byte("sometag[123]: foo bar baz blah quux")

	p := NewParser(buff)

	for i := 0; i < b.N; i++ {
		_, err := p.parsemessage()
		if err != parsercommon.ErrEOL {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseFull(b *testing.B) {
	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"

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
