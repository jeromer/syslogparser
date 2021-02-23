package rfc5424

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/parsercommon"
)

const (
	NILVALUE = '-'

	// according to https://tools.ietf.org/html/rfc5424#section-6.1
	// the length of the packet MUST be 2048 bytes or less.
	// However we will accept a bit more while protecting from exhaustion
	MAX_PACKET_LEN = 3048
)

var (
	ErrYearInvalid       = &parsercommon.ParserError{ErrorString: "Invalid year in timestamp"}
	ErrMonthInvalid      = &parsercommon.ParserError{ErrorString: "Invalid month in timestamp"}
	ErrDayInvalid        = &parsercommon.ParserError{ErrorString: "Invalid day in timestamp"}
	ErrHourInvalid       = &parsercommon.ParserError{ErrorString: "Invalid hour in timestamp"}
	ErrMinuteInvalid     = &parsercommon.ParserError{ErrorString: "Invalid minute in timestamp"}
	ErrSecondInvalid     = &parsercommon.ParserError{ErrorString: "Invalid second in timestamp"}
	ErrSecFracInvalid    = &parsercommon.ParserError{ErrorString: "Invalid fraction of second in timestamp"}
	ErrTimeZoneInvalid   = &parsercommon.ParserError{ErrorString: "Invalid time zone in timestamp"}
	ErrInvalidTimeFormat = &parsercommon.ParserError{ErrorString: "Invalid time format"}
	ErrInvalidAppName    = &parsercommon.ParserError{ErrorString: "Invalid app name"}
	ErrInvalidProcId     = &parsercommon.ParserError{ErrorString: "Invalid proc ID"}
	ErrInvalidMsgId      = &parsercommon.ParserError{ErrorString: "Invalid msg ID"}
	ErrNoStructuredData  = &parsercommon.ParserError{ErrorString: "No structured data"}
)

type Parser struct {
	buff           []byte
	cursor         int
	l              int
	header         *header
	structuredData string
	message        string

	tmpHostname string
	tmpPriority *parsercommon.Priority
}

type header struct {
	priority  *parsercommon.Priority
	version   int
	timestamp time.Time
	hostname  string
	appName   string
	procId    string
	msgId     string
}

type partialTime struct {
	hour    int
	minute  int
	seconds int
	secFrac float64
}

type fullTime struct {
	pt  *partialTime
	loc *time.Location
}

type fullDate struct {
	year  int
	month int
	day   int
}

func NewParser(buff []byte) *Parser {
	return &Parser{
		buff:   buff,
		cursor: 0,
		l: int(
			math.Min(
				float64(len(buff)),
				MAX_PACKET_LEN,
			),
		),
	}
}

// Forces a priority for this parser. Priority will not be parsed.
func (p *Parser) WithPriority(pri *parsercommon.Priority) {
	p.tmpPriority = pri
}

// Noop as RFC5424 syslog always has a timezone
func (p *Parser) WithLocation(l *time.Location) {}

// Noop as RFC5424 is strict about timestamp format
func (p *Parser) WithTimestampFormat(s string) {}

// Forces a hostname. Hostname will not be parsed
func (p *Parser) WithHostname(h string) {
	p.tmpHostname = h
}

// Noop as RFC5424 as no tag per se:
// The TAG has been split into APP-NAME, PROCID, and MSGID.
// Ref: https://tools.ietf.org/html/rfc5424#appendix-A.1
func (p *Parser) WithTag(t string) {
}

// DEPRECATED. Use WithLocation() instead
func (p *Parser) Location(location *time.Location) {
}

func (p *Parser) Parse() error {
	hdr, err := p.parseHeader()
	if err != nil {
		return err
	}

	p.header = hdr

	sd, err := p.parseStructuredData()
	if err != nil {
		return err
	}

	p.structuredData = sd
	p.cursor++

	if p.cursor < p.l {
		p.message = string(
			bytes.Trim(
				p.buff[p.cursor:p.l], " ",
			),
		)
	}

	return nil
}

func (p *Parser) Dump() syslogparser.LogParts {
	return syslogparser.LogParts{
		"priority":        p.header.priority.P,
		"facility":        p.header.priority.F.Value,
		"severity":        p.header.priority.S.Value,
		"version":         p.header.version,
		"timestamp":       p.header.timestamp,
		"hostname":        p.header.hostname,
		"app_name":        p.header.appName,
		"proc_id":         p.header.procId,
		"msg_id":          p.header.msgId,
		"structured_data": p.structuredData,
		"message":         p.message,
	}
}

// HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
func (p *Parser) parseHeader() (*header, error) {
	pri, err := p.parsePriority()
	if err != nil {
		return nil, err
	}

	ver, err := p.parseVersion()
	if err != nil {
		return nil, err
	}

	p.cursor++

	ts, err := p.parseTimestamp()
	if err != nil {
		return nil, err
	}

	p.cursor++

	host, err := p.parseHostname()
	if err != nil {
		return nil, err
	}

	// cursor is moved in p.parseHostname()

	appName, err := p.parseAppName()
	if err != nil {
		return nil, err
	}

	p.cursor++

	procId, err := p.parseProcId()
	if err != nil {
		return nil, err
	}

	p.cursor++

	msgId, err := p.parseMsgId()
	if err != nil {
		return nil, err
	}

	p.cursor++

	hdr := &header{
		version:   ver,
		timestamp: *ts,
		priority:  pri,
		hostname:  host,
		procId:    procId,
		msgId:     msgId,
		appName:   appName,
	}

	return hdr, nil
}

func (p *Parser) parsePriority() (*parsercommon.Priority, error) {
	if p.tmpPriority != nil {
		return p.tmpPriority, nil
	}

	return parsercommon.ParsePriority(
		p.buff, &p.cursor, p.l,
	)
}

func (p *Parser) parseVersion() (int, error) {
	return parsercommon.ParseVersion(p.buff, &p.cursor, p.l)
}

// https://tools.ietf.org/html/rfc5424#section-6.2.3
func (p *Parser) parseTimestamp() (*time.Time, error) {
	if p.buff[p.cursor] == NILVALUE {
		p.cursor++
		return new(time.Time), nil
	}

	fd, err := parseFullDate(
		p.buff, &p.cursor, p.l,
	)

	if err != nil {
		return nil, err
	}

	if p.buff[p.cursor] != 'T' {
		return nil, ErrInvalidTimeFormat
	}

	p.cursor++

	ft, err := parseFullTime(
		p.buff, &p.cursor, p.l,
	)

	if err != nil {
		return nil, parsercommon.ErrTimestampUnknownFormat
	}

	nSec, err := toNSec(
		ft.pt.secFrac,
	)

	if err != nil {
		return nil, err
	}

	ts := time.Date(
		fd.year,
		time.Month(fd.month),
		fd.day,
		ft.pt.hour,
		ft.pt.minute,
		ft.pt.seconds,
		nSec,
		ft.loc,
	)

	return &ts, nil
}

// HOSTNAME = NILVALUE / 1*255PRINTUSASCII
func (p *Parser) parseHostname() (string, error) {
	if p.tmpHostname != "" {
		return p.tmpHostname, nil
	}

	h, err := parsercommon.ParseHostname(p.buff, &p.cursor, p.l)

	p.cursor++

	return h, err
}

// APP-NAME = NILVALUE / 1*48PRINTUSASCII
func (p *Parser) parseAppName() (string, error) {
	return parseUpToLen(p.buff, &p.cursor, p.l, 48, ErrInvalidAppName)
}

// PROCID = NILVALUE / 1*128PRINTUSASCII
func (p *Parser) parseProcId() (string, error) {
	return parseUpToLen(p.buff, &p.cursor, p.l, 128, ErrInvalidProcId)
}

// MSGID = NILVALUE / 1*32PRINTUSASCII
func (p *Parser) parseMsgId() (string, error) {
	return parseUpToLen(
		p.buff, &p.cursor, p.l, 32, ErrInvalidMsgId,
	)
}

func (p *Parser) parseStructuredData() (string, error) {
	return parseStructuredData(p.buff, &p.cursor, p.l)
}

// ----------------------------------------------
// https://tools.ietf.org/html/rfc5424#section-6
// ----------------------------------------------

// XXX : bind them to Parser ?

// FULL-DATE : DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
func parseFullDate(buff []byte, cursor *int, l int) (fullDate, error) {
	var fd fullDate

	year, err := parseYear(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if buff[*cursor] != '-' {
		return fd, parsercommon.ErrTimestampUnknownFormat
	}

	*cursor++

	month, err := parseMonth(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if buff[*cursor] != '-' {
		return fd, parsercommon.ErrTimestampUnknownFormat
	}

	*cursor++

	day, err := parseDay(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	fd = fullDate{
		year:  year,
		month: month,
		day:   day,
	}

	return fd, nil
}

// DATE-FULLYEAR   = 4DIGIT
func parseYear(buff []byte, cursor *int, l int) (int, error) {
	yearLen := 4

	if *cursor+yearLen > l {
		return 0, parsercommon.ErrEOL
	}

	// XXX : we do not check for a valid year (ie. 1999, 2013 etc)
	// XXX : we only checks the format is correct
	sub := string(buff[*cursor : *cursor+yearLen])

	*cursor += yearLen

	year, err := strconv.Atoi(sub)
	if err != nil {
		return 0, ErrYearInvalid
	}

	return year, nil
}

// DATE-MONTH = 2DIGIT  ; 01-12
func parseMonth(buff []byte, cursor *int, l int) (int, error) {
	return parsercommon.Parse2Digits(buff, cursor, l, 1, 12, ErrMonthInvalid)
}

// DATE-MDAY = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year
func parseDay(buff []byte, cursor *int, l int) (int, error) {
	// XXX : this is a relaxed constraint
	// XXX : we do not check if valid regarding February or leap years
	// XXX : we only checks that day is in range [01 -> 31]
	// XXX : in other words this function will not rant if you provide Feb 31th
	return parsercommon.Parse2Digits(buff, cursor, l, 1, 31, ErrDayInvalid)
}

// FULL-TIME = PARTIAL-TIME TIME-OFFSET
func parseFullTime(buff []byte, cursor *int, l int) (*fullTime, error) {
	pt, err := parsePartialTime(buff, cursor, l)
	if err != nil {
		return nil, err
	}

	loc, err := parseTimeOffset(buff, cursor, l)
	if err != nil {
		return nil, err
	}

	ft := &fullTime{
		pt:  pt,
		loc: loc,
	}

	return ft, nil
}

// PARTIAL-TIME = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND[TIME-SECFRAC]
func parsePartialTime(buff []byte, cursor *int, l int) (*partialTime, error) {
	hour, minute, err := getHourMinute(
		buff, cursor, l,
	)

	if err != nil {
		return nil, err
	}

	if buff[*cursor] != ':' {
		return nil, ErrInvalidTimeFormat
	}

	*cursor++

	// ----

	seconds, err := parseSecond(
		buff, cursor, l,
	)

	if err != nil {
		return nil, err
	}

	pt := &partialTime{
		hour:    hour,
		minute:  minute,
		seconds: seconds,
	}

	// ----

	if buff[*cursor] != '.' {
		return pt, nil
	}

	*cursor++

	secFrac, err := parseSecFrac(
		buff, cursor, l,
	)

	if err != nil {
		return pt, nil
	}

	pt.secFrac = secFrac

	return pt, nil
}

// TIME-HOUR = 2DIGIT  ; 00-23
func parseHour(buff []byte, cursor *int, l int) (int, error) {
	return parsercommon.Parse2Digits(buff, cursor, l, 0, 23, ErrHourInvalid)
}

// TIME-MINUTE = 2DIGIT  ; 00-59
func parseMinute(buff []byte, cursor *int, l int) (int, error) {
	return parsercommon.Parse2Digits(buff, cursor, l, 0, 59, ErrMinuteInvalid)
}

// TIME-SECOND = 2DIGIT  ; 00-59
func parseSecond(buff []byte, cursor *int, l int) (int, error) {
	return parsercommon.Parse2Digits(buff, cursor, l, 0, 59, ErrSecondInvalid)
}

// TIME-SECFRAC = "." 1*6DIGIT
func parseSecFrac(buff []byte, cursor *int, l int) (float64, error) {
	maxDigitLen := 6

	max := *cursor + maxDigitLen
	from := *cursor
	to := 0

	for to = from; to < max; to++ {
		if to >= l {
			break
		}

		c := buff[to]
		if !parsercommon.IsDigit(c) {
			break
		}
	}

	sub := string(buff[from:to])
	if len(sub) == 0 {
		return 0, ErrSecFracInvalid
	}

	secFrac, err := strconv.ParseFloat("0."+sub, 64)
	*cursor = to
	if err != nil {
		return 0, ErrSecFracInvalid
	}

	return secFrac, nil
}

// TIME-OFFSET = "Z" / TIME-NUMOFFSET
func parseTimeOffset(buff []byte, cursor *int, l int) (*time.Location, error) {

	if buff[*cursor] == 'Z' {
		*cursor++
		return time.UTC, nil
	}

	return parseNumericalTimeOffset(buff, cursor, l)
}

// TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE
func parseNumericalTimeOffset(buff []byte, cursor *int, l int) (*time.Location, error) {
	var loc = new(time.Location)

	sign := buff[*cursor]

	if (sign != '+') && (sign != '-') {
		return loc, ErrTimeZoneInvalid
	}

	*cursor++

	hour, minute, err := getHourMinute(buff, cursor, l)
	if err != nil {
		return loc, err
	}

	tzStr := fmt.Sprintf("%s%02d:%02d", string(sign), hour, minute)
	tmpTs, err := time.Parse("-07:00", tzStr)
	if err != nil {
		return loc, err
	}

	return tmpTs.Location(), nil
}

func getHourMinute(buff []byte, cursor *int, l int) (int, int, error) {
	hour, err := parseHour(buff, cursor, l)
	if err != nil {
		return 0, 0, err
	}

	if buff[*cursor] != ':' {
		return 0, 0, ErrInvalidTimeFormat
	}

	*cursor++

	minute, err := parseMinute(buff, cursor, l)
	if err != nil {
		return 0, 0, err
	}

	return hour, minute, nil
}

func toNSec(sec float64) (int, error) {
	_, frac := math.Modf(sec)
	fracStr := strconv.FormatFloat(frac, 'f', 9, 64)
	fracInt, err := strconv.Atoi(fracStr[2:])
	if err != nil {
		return 0, err
	}

	return fracInt, nil
}

// ------------------------------------------------
// https://tools.ietf.org/html/rfc5424#section-6.3
// ------------------------------------------------

func parseStructuredData(buff []byte, cursor *int, l int) (string, error) {
	var sdData string
	var found bool

	if buff[*cursor] == NILVALUE {
		*cursor++
		return "-", nil
	}

	if buff[*cursor] != '[' {
		return sdData, ErrNoStructuredData
	}

	from := *cursor
	to := 0

	for to = from; to < l; to++ {
		if found {
			break
		}

		b := buff[to]

		if b == ']' {
			switch t := to + 1; {
			case t == l:
				found = true
			case t <= l && buff[t] == ' ':
				found = true
			}
		}
	}

	if found {
		*cursor = to
		return string(buff[from:to]), nil
	}

	return sdData, ErrNoStructuredData
}

func parseUpToLen(buff []byte, cursor *int, l int, maxLen int, e error) (string, error) {
	var to int
	var found bool
	var result string

	max := *cursor + maxLen

	for to = *cursor; (to < max) && (to < l); to++ {
		if buff[to] == ' ' {
			found = true
			break
		}
	}

	if found {
		result = string(buff[*cursor:to])
	}

	*cursor = to

	if found {
		return result, nil
	}

	return "", e
}
