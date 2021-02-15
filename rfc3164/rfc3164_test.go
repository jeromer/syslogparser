package rfc3164

import (
	"bytes"
	"testing"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/stretchr/testify/suite"
)

type RFC3164TestSuite struct {
	suite.Suite
}

var (
	// XXX : corresponds to the length of the last tried timestamp format
	// XXX : Jan  2 15:04:05
	lastTriedTimestampLen = 15
)

func (s *RFC3164TestSuite) TestParser_Valid() {
	buff := []byte(
		"<34>Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
	)

	p := NewParser(buff)
	s.Require().Equal(
		p,
		&Parser{
			buff:          buff,
			cursor:        0,
			l:             len(buff),
			location:      time.UTC,
			ParsePriority: true,
		},
	)

	err := p.Parse()
	s.Require().Nil(err)
	s.Require().Equal(
		p.Dump(),
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
	)
}

func (s *RFC3164TestSuite) TestParser_WithoutPriority() {
	buff := []byte(
		"Oct 11 22:14:15 mymachine very.large.syslog.message.tag: 'su root' failed for lonvick on /dev/pts/8",
	)

	p := NewParser(buff)
	p.ParsePriority = false

	s.Require().Equal(
		p,
		&Parser{
			buff:          buff,
			cursor:        0,
			l:             len(buff),
			location:      time.UTC,
			ParsePriority: false,
		},
	)

	err := p.Parse()
	s.Require().Nil(err)
	s.Require().Equal(
		p.Dump(),
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
		},
	)
}

func (s *RFC3164TestSuite) TestParseWithout_Hostname() {
	buff := []byte(
		"<30>Jun 23 13:17:42 chronyd[1119]: Selected source 192.168.65.1",
	)

	p := NewParser(buff)
	p.Hostname("testhost")

	err := p.Parse()
	s.Require().Nil(err)

	s.Require().Equal(
		p.Dump(),
		syslogparser.LogParts{
			"timestamp": time.Date(
				time.Now().Year(),
				time.June,
				23, 13, 17, 42, 0,
				time.UTC,
			),
			"hostname": "testhost",
			"tag":      "chronyd",
			"content":  "Selected source 192.168.65.1",
			"priority": 30,
			"facility": 3,
			"severity": 6,
		},
	)
}

func (s *RFC3164TestSuite) TestParseHeader() {
	testCases := []struct {
		description       string
		input             []byte
		expectedHdr       header
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description: "valid headers",
			input:       []byte("Oct 11 22:14:15 mymachine "),
			expectedHdr: header{
				hostname: "mymachine",
				timestamp: time.Date(
					time.Now().Year(),
					time.October,
					11, 22, 14, 15, 0,
					time.UTC,
				),
			},
			expectedCursorPos: 25,
			expectedErr:       nil,
		},
		{
			description:       "invalid timestamp",
			input:             []byte("Oct 34 32:72:82 mymachine "),
			expectedHdr:       header{},
			expectedCursorPos: lastTriedTimestampLen + 1,
			expectedErr:       syslogparser.ErrTimestampUnknownFormat,
		},
	}

	for _, tc := range testCases {
		p := NewParser(tc.input)
		obtained, err := p.parseHeader()

		s.Require().Equal(err, tc.expectedErr, tc.description)
		s.Require().Equal(obtained, tc.expectedHdr, tc.description)
		s.Require().Equal(p.cursor, tc.expectedCursorPos, tc.description)
	}
}

func (s *RFC3164TestSuite) TestParsemessage_Valid() {
	content := "foo bar baz blah quux"

	buff := []byte("sometag[123]: " + content)

	hdr := rfc3164message{
		tag:     "sometag",
		content: content,
	}

	p := NewParser(buff)
	obtained, err := p.parsemessage()

	s.Require().Equal(err, syslogparser.ErrEOL)
	s.Require().Equal(obtained, hdr)
	s.Require().Equal(p.cursor, len(buff))
}

func (s *RFC3164TestSuite) TestParseTimestamp() {
	testCases := []struct {
		description       string
		input             []byte
		expectedTS        time.Time
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "invalid",
			input:             []byte("Oct 34 32:72:82"),
			expectedCursorPos: lastTriedTimestampLen,
			expectedErr:       syslogparser.ErrTimestampUnknownFormat,
		},
		{
			description: "trailing space",
			input:       []byte("Oct 11 22:14:15 "),
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
			input:       []byte("Oct  1 22:14:15"),
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
			input:       []byte("Oct 11 22:14:15"),
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
		p := NewParser(tc.input)
		obtained, err := p.parseTimestamp()

		s.Require().Equal(
			obtained, tc.expectedTS, tc.description,
		)
		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)
		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
	}
}

func (s *RFC3164TestSuite) TestParseTag() {
	testCases := []struct {
		description       string
		input             []byte
		expectedTag       string
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "with pid",
			input:             []byte("apache2[10]:"),
			expectedTag:       "apache2",
			expectedCursorPos: 12,
			expectedErr:       nil,
		},
		{
			description:       "without pid",
			input:             []byte("apache2:"),
			expectedTag:       "apache2",
			expectedCursorPos: 8,
			expectedErr:       nil,
		},
		{
			description:       "trailing space",
			input:             []byte("apache2: "),
			expectedTag:       "apache2",
			expectedCursorPos: 9,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		p := NewParser(tc.input)
		obtained, err := p.parseTag()

		s.Require().Equal(
			obtained, tc.expectedTag, tc.description,
		)

		s.Require().Equal(
			p.cursor, tc.expectedCursorPos, tc.description,
		)

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
	}
}

func (s *RFC3164TestSuite) TestParseContent_Valid() {
	buff := []byte(" foo bar baz quux ")
	content := string(bytes.Trim(buff, " "))

	p := NewParser(buff)
	obtained, err := p.parseContent()

	s.Require().Equal(err, syslogparser.ErrEOL)
	s.Require().Equal(obtained, content)
	s.Require().Equal(p.cursor, len(content))
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
		if err != syslogparser.ErrEOL {
			panic(err)
		}

		p.cursor = 0
	}
}

func BenchmarkParseFull(b *testing.B) {
	msg := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"

	p := NewParser([]byte(msg))

	for i := 0; i < b.N; i++ {
		_, err := p.parsemessage()
		if err != syslogparser.ErrEOL {
			panic(err)
		}

		p.cursor = 0
	}

}

func TestRFC3164TestSuite(t *testing.T) {
	suite.Run(
		t, new(RFC3164TestSuite),
	)
}
