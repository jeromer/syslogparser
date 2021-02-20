// Package syslogparser implements functions to parsing RFC3164 or RFC5424 syslog messages.
// syslogparser provides one subpackage per RFC with an example usage for which RFC.
package syslogparser

import (
	"time"

	"github.com/jeromer/syslogparser/parsercommon"
)

type RFC uint8

const (
	RFC_UNKNOWN = iota
	RFC_3164
	RFC_5424
)

type LogParts map[string]interface{}

type LogParser interface {
	Parse() error
	Dump() LogParts
	Location(*time.Location)
	Hostname(string)
}

func DetectRFC(buff []byte) (RFC, error) {
	max := 10
	var v int
	var err error

	for i := 0; i < max; i++ {
		if buff[i] == '>' && i < max {
			x := i + 1

			v, err = parsercommon.ParseVersion(
				buff, &x, max,
			)

			break
		}
	}

	if err != nil {
		return RFC_UNKNOWN, err
	}

	if v == parsercommon.NO_VERSION {
		return RFC_3164, nil
	}

	return RFC_5424, nil
}
