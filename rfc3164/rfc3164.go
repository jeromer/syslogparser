package rfc3164

import (
	"bytes"
	"math"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/parsercommon"
)

const (
	// according to https://tools.ietf.org/html/rfc3164#section-4.1
	// "The total length of the packet MUST be 1024 bytes or less"
	// However we will accept a bit more while protecting from exhaustion
	MAX_PACKET_LEN = 2048
)

type Parser struct {
	buff          []byte
	cursor        int
	l             int
	priority      *parsercommon.Priority
	version       int
	header        *header
	message       *message
	location      *time.Location
	hostname      string
	ParsePriority bool
}

type header struct {
	timestamp time.Time
	hostname  string
}

type message struct {
	tag     string
	content string
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:          buff,
		cursor:        0,
		location:      time.UTC,
		ParsePriority: true,
		l: int(
			math.Min(
				float64(len(buff)),
				MAX_PACKET_LEN,
			),
		),
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

func (p *Parser) Hostname(hostname string) {
	p.hostname = hostname
}

func (p *Parser) Parse() error {
	p.priority = &parsercommon.Priority{
		P: 0,
		F: parsercommon.Facility{Value: 0},
		S: parsercommon.Severity{Value: 0},
	}

	if p.ParsePriority {
		pri, err := p.parsePriority()
		if err != nil {
			return err
		}

		p.priority = pri
	}

	hdr, err := p.parseHeader()
	if err != nil {
		return err
	}

	if p.buff[p.cursor] == ' ' {
		p.cursor++
	}

	msg, err := p.parsemessage()
	if err != parsercommon.ErrEOL {
		return err
	}

	p.version = parsercommon.NO_VERSION
	p.header = hdr
	p.message = msg

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	parts := syslogparser.LogParts{
		"timestamp": p.header.timestamp,
		"hostname":  p.header.hostname,
		"tag":       p.message.tag,
		"content":   p.message.content,
	}

	if p.ParsePriority {
		parts["priority"] = p.priority.P
		parts["facility"] = p.priority.F.Value
		parts["severity"] = p.priority.S.Value
	}

	return parts
}

func (p *Parser) parsePriority() (*parsercommon.Priority, error) {
	return parsercommon.ParsePriority(
		p.buff, &p.cursor, p.l,
	)
}

// HEADER: TIMESTAMP + HOSTNAME (or IP)
// https://tools.ietf.org/html/rfc3164#section-4.1.2
func (p *Parser) parseHeader() (*header, error) {
	var err error

	if p.buff[p.cursor] == ' ' {
		p.cursor++
	}

	ts, err := p.parseTimestamp()
	if err != nil {
		return nil, err
	}

	hostname, err := p.parseHostname()
	if err != nil {
		return nil, err
	}

	h := &header{
		timestamp: ts,
		hostname:  hostname,
	}

	return h, nil
}

// MSG: TAG + CONTENT
// https://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parsemessage() (*message, error) {
	var err error

	tag, err := p.parseTag()
	if err != nil {
		return nil, err
	}

	content, err := p.parseContent()
	if err != parsercommon.ErrEOL {
		return nil, err
	}

	msg := &message{
		tag:     tag,
		content: content,
	}

	return msg, err
}

// https://tools.ietf.org/html/rfc3164#section-4.1.2
func (p *Parser) parseTimestamp() (time.Time, error) {
	var ts time.Time
	var err error
	var tsFmtLen int
	var sub []byte

	tsFmts := []string{
		"Jan 02 15:04:05",
		"Jan  2 15:04:05",
	}

	found := false
	for _, tsFmt := range tsFmts {
		tsFmtLen = len(tsFmt)

		if p.cursor+tsFmtLen > p.l {
			continue
		}

		sub = p.buff[p.cursor : tsFmtLen+p.cursor]
		ts, err = time.ParseInLocation(
			tsFmt, string(sub), p.location,
		)

		if err == nil {
			found = true
			break
		}
	}

	if !found {
		p.cursor = tsFmtLen

		// XXX : If the timestamp is invalid we try to push the cursor one byte
		// XXX : further, in case it is a space
		if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
			p.cursor++
		}

		return ts, parsercommon.ErrTimestampUnknownFormat
	}

	fixTimestampIfNeeded(&ts)

	p.cursor += tsFmtLen

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return ts, nil
}

func (p *Parser) parseHostname() (string, error) {
	if p.hostname != "" {
		return p.hostname, nil
	}

	return parsercommon.ParseHostname(
		p.buff, &p.cursor, p.l,
	)
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parseTag() (string, error) {
	var b byte
	var endOfTag bool
	var bracketOpen bool
	var tag []byte
	var err error
	var found bool

	from := p.cursor

	for {
		b = p.buff[p.cursor]
		bracketOpen = (b == '[')
		endOfTag = (b == ':' || b == ' ')

		// XXX : parse PID ?
		if bracketOpen {
			tag = p.buff[from:p.cursor]
			found = true
		}

		if endOfTag {
			if !found {
				tag = p.buff[from:p.cursor]
				// found = true
			}

			p.cursor++
			break
		}

		p.cursor++
	}

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return string(tag), err
}

func (p *Parser) parseContent() (string, error) {
	if p.cursor > p.l {
		return "", parsercommon.ErrEOL
	}

	content := bytes.Trim(
		p.buff[p.cursor:p.l], " ",
	)

	p.cursor += len(content)

	return string(content), parsercommon.ErrEOL
}

func fixTimestampIfNeeded(ts *time.Time) {
	now := time.Now()
	y := ts.Year()

	if ts.Year() == 0 {
		y = now.Year()
	}

	newTs := time.Date(
		y, ts.Month(), ts.Day(),
		ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(),
		ts.Location(),
	)

	*ts = newTs
}
