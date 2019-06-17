package rfc3164

import (
	"bytes"
	"github.com/jeromer/syslogparser"
	"time"
	"fmt"
)

type Parser struct {
	buff          []byte
	cursor        int
	l             int
	priority      syslogparser.Priority
	version       int
	header        header
	message       rfc3164message
	location      *time.Location
	hostname      string
	ParsePriority bool
}

type header struct {
	timestamp time.Time
	hostname  string
}

type rfc3164message struct {
	tag     string
	content string
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:          buff,
		cursor:        0,
		l:             len(buff),
		location:      time.UTC,
		ParsePriority: true,
	}
}

func (p *Parser) Location(location *time.Location) {
	p.location = location
}

func (p *Parser) Hostname(hostname string) {
	p.hostname = hostname
}

func (p *Parser) Parse() error {
	if p.ParsePriority {
		pri, err := p.parsePriority()
		if err != nil {
			return err
		}
		p.priority = pri
	} else {
		p.priority = syslogparser.Priority{
			0,
			syslogparser.Facility{0},
			syslogparser.Severity{0},
		}
	}

	hdr, err := p.parseHeader()
	if err != nil {
		return err
	}

	if p.buff[p.cursor] == ' ' {
		p.cursor++
	}

	msg, err := p.parsemessage()
	if err != syslogparser.ErrEOL {
		return err
	}

	p.version = syslogparser.NO_VERSION
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

func (p *Parser) parsePriority() (syslogparser.Priority, error) {
	return syslogparser.ParsePriority(p.buff, &p.cursor, p.l)
}

func (p *Parser) parseHeader() (header, error) {
	hdr := header{}
	var err error

	ts, err := p.parseTimestamp()
	if err != nil {
		return hdr, err
	}

	hostname, err := p.parseHostname()
	if err != nil {
		return hdr, err
	}

	hdr.timestamp = ts
	hdr.hostname = hostname

	return hdr, nil
}

func (p *Parser) parsemessage() (rfc3164message, error) {
	msg := rfc3164message{}
	var err error

	tag, cursor, err := p.parseTag()
	if err != nil {
		p.cursor = cursor
	}

	content, err := p.parseContent()
	if err != syslogparser.ErrEOL {
		return msg, err
	}

	msg.tag = tag
	msg.content = content

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
		ts, err = time.ParseInLocation(tsFmt, string(sub), p.location)
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

		return ts, syslogparser.ErrTimestampUnknownFormat
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
	} else {
		return syslogparser.ParseHostname(p.buff, &p.cursor, p.l)
	}
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser) parseTag() (string, int, error) {
	var b byte
	var endOfTag bool
	var bracketOpen bool
	var tag []byte
	var err error
	var found bool

	from := p.cursor

	for {
		if p.l <= p.cursor {
			err = fmt.Errorf("No tag")
			tag = []byte("")
			break
		}
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
				found = true
			}

			p.cursor++
			break
		}

		p.cursor++
	}

	if (p.cursor < p.l) && (p.buff[p.cursor] == ' ') {
		p.cursor++
	}

	return string(tag), from, err
}

func (p *Parser) parseContent() (string, error) {
	if p.cursor > p.l {
		return "", syslogparser.ErrEOL
	}

	content := bytes.Trim(p.buff[p.cursor:p.l], " ")
	p.cursor += len(content)

	return string(content), syslogparser.ErrEOL
}

func fixTimestampIfNeeded(ts *time.Time) {
	now := time.Now()
	y := ts.Year()

	if ts.Year() == 0 {
		y = now.Year()
	}

	newTs := time.Date(y, ts.Month(), ts.Day(), ts.Hour(), ts.Minute(),
		ts.Second(), ts.Nanosecond(), ts.Location())

	*ts = newTs
}
