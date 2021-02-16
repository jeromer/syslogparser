Syslogparser
============

This is a syslog parser for the Go programming language.

Installing
----------

go get github.com/jeromer/syslogparser

Supported RFCs
--------------

- [RFC 3164][RFC 3164]
- [RFC 5424][RFC 5424]

Not all features described in RFCs above are supported but only the most
part of it. For exaple `SDID`s are not supported in [RFC 5424][RFC 5424] and
`STRUCTURED-DATA` are parsed as a whole string.

This parser should solve 80% of use cases. If your use cases are in the
20% remaining ones I would recommend you to fully test what you want to
achieve and provide a patch if you want.

Parsing an RFC 3164 syslog message
----------------------------------

	b := "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
	buff := []byte(b)

	p := rfc3164.NewParser(buff)
	err := p.Parse()
	if err != nil {
		panic(err)
	}

	for k, v := range p.Dump() {
		fmt.Println(k, ":", v)
	}

You should see

    timestamp : 2013-10-11 22:14:15 +0000 UTC
    hostname  : mymachine
    tag       : su
    content   : 'su root' failed for lonvick on /dev/pts/8
    priority  : 34
    facility  : 4
    severity  : 2

Parsing an RFC 5424 syslog message
----------------------------------

	b := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry...`
	buff := []byte(b)

	p := rfc5424.NewParser(buff)
	err := p.Parse()
	if err != nil {
		panic(err)
	}

	for k, v := range p.Dump() {
		fmt.Println(k, ":", v)
	}

You should see

    version : 1
    timestamp : 2003-10-11 22:14:15.003 +0000 UTC
    app_name : evntslog
    msg_id : ID47
    message : An application event log entry...
    priority : 165
    facility : 20
    severity : 5
    hostname : mymachine.example.com
    proc_id : -
    structured_data : [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]

Detecting message format
------------------------

You can use the `DetectRFC()` function. Like this:

	b := []byte(`<165>1 2003-10-11T22:14:15.003Z ...`)
	rfc, err := syslogparser.DetectRFC(b)
	if err != nil {
		panic(err)
	}

	switch rfc {
	case RFC_UNKNOWN:
		fmt.Println("unknown")
	case RFC_3164:
		fmt.Println("3164")
	case RFC_5424:
		fmt.Println("5424")
	}

Running tests
-------------

Run `make test`

Running benchmarks
------------------

Run `make benchmark`

    go test -bench=. -benchmem
    goos: linux
    goarch: amd64
    pkg: github.com/jeromer/syslogparser
    BenchmarkParsePriority-8   	41772079	        31.2 ns/op	       0 B/op	       0 allocs/op
    BenchmarkParseVersion-8    	270007530	         4.45 ns/op	       0 B/op	       0 allocs/op
    BenchmarkDetectRFC-8       	78742269	        16.2 ns/op	       0 B/op	       0 allocs/op
    PASS
    ok  	github.com/jeromer/syslogparser	5.257s

    cd rfc3164 && go test -bench=. -benchmem
    goos: linux
    goarch: amd64
    pkg: github.com/jeromer/syslogparser/rfc3164
    BenchmarkParseTimestamp-8   	 2693362	       467 ns/op	      16 B/op	       1 allocs/op
    BenchmarkParseHostname-8    	34919636	        32.8 ns/op	      16 B/op	       1 allocs/op
    BenchmarkParseTag-8         	20970715	        56.0 ns/op	       8 B/op	       1 allocs/op
    BenchmarkParseHeader-8      	 2549106	       478 ns/op	      32 B/op	       2 allocs/op
    BenchmarkParsemessage-8     	 8280796	       143 ns/op	      72 B/op	       3 allocs/op
    BenchmarkParseFull-8        	 8070195	       139 ns/op	     120 B/op	       3 allocs/op
    PASS
    ok  	github.com/jeromer/syslogparser/rfc3164	8.428s

    cd rfc5424 && go test -bench=. -benchmem
    goos: linux
    goarch: amd64
    pkg: github.com/jeromer/syslogparser/rfc5424
    BenchmarkParseTimestamp-8   	  846019	      1385 ns/op	     352 B/op	      18 allocs/op
    BenchmarkParseHeader-8      	 1424103	       840 ns/op	     106 B/op	      12 allocs/op
    BenchmarkParseFull-8        	 1444834	       825 ns/op	     112 B/op	      12 allocs/op
    PASS
    ok  	github.com/jeromer/syslogparser/rfc5424	6.195s

[RFC 5424]: https://tools.ietf.org/html/rfc5424
[RFC 3164]: https://tools.ietf.org/html/rfc3164
