package syslogparser

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type CommonTestSuite struct {
	suite.Suite
}

func (s *CommonTestSuite) TestParsePriority() {
	testCases := []struct {
		description       string
		input             []byte
		expectedPri       Priority
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "empty priority",
			input:             []byte(""),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityEmpty,
		},
		{
			description:       "no start",
			input:             []byte("7>"),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNoStart,
		},
		{
			description:       "no end",
			input:             []byte("<77"),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNoEnd,
		},
		{
			description:       "too short",
			input:             []byte("<>"),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityTooShort,
		},
		{
			description:       "too long",
			input:             []byte("<1233>"),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityTooLong,
		},
		{
			description:       "no digits",
			input:             []byte("<7a8>"),
			expectedPri:       newPriority(0),
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNonDigit,
		},
		{
			description:       "all good",
			input:             []byte("<190>"),
			expectedPri:       newPriority(190),
			expectedCursorPos: 5,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0

		obtained, err := ParsePriority(
			tc.input, &cursor, len(tc.input),
		)

		s.Require().Equal(
			obtained, tc.expectedPri, tc.description,
		)

		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
	}
}

func (s *CommonTestSuite) TestNewPriority() {
	s.Require().Equal(
		newPriority(165),
		Priority{
			P: 165,
			F: Facility{Value: 20},
			S: Severity{Value: 5},
		},
	)
}

func (s *CommonTestSuite) TestParseVersion() {
	testCases := []struct {
		description       string
		input             []byte
		expectedVersion   int
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "not found",
			input:             []byte("<123>"),
			expectedVersion:   NO_VERSION,
			expectedCursorPos: 5,
			expectedErr:       ErrVersionNotFound,
		},
		{
			description:       "non digit",
			input:             []byte("<123>a"),
			expectedVersion:   NO_VERSION,
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
		{
			description:       "all good",
			input:             []byte("<123>1"),
			expectedVersion:   1,
			expectedCursorPos: 6,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 5

		obtained, err := ParseVersion(
			tc.input, &cursor, len(tc.input),
		)

		s.Require().Equal(
			obtained, tc.expectedVersion, tc.description,
		)

		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
	}
}

func (s *CommonTestSuite) TestParseHostname() {
	testCases := []struct {
		description       string
		input             []byte
		expectedHostname  string
		expectedCursorPos int
	}{
		{
			description:       "invalid",
			input:             []byte("foo name"),
			expectedHostname:  "foo",
			expectedCursorPos: 3,
		},
		{
			description:       "valid",
			input:             []byte("ubuntu11.somehost.com" + " "),
			expectedHostname:  "ubuntu11.somehost.com",
			expectedCursorPos: len("ubuntu11.somehost.com"),
		},
	}

	for _, tc := range testCases {
		cursor := 0

		obtained, err := ParseHostname(
			tc.input, &cursor, len(tc.input),
		)

		s.Require().Equal(
			obtained, tc.expectedHostname, tc.description,
		)

		s.Require().Equal(
			cursor, tc.expectedCursorPos, tc.description,
		)

		s.Require().Nil(err)
	}
}

func (s *CommonTestSuite) TestDetectRFC_3164() {
	p, err := DetectRFC([]byte("<34>Oct 11 22:14:15 ..."))

	s.Require().Nil(err)
	s.Require().Equal(p, RFC(RFC_3164))
}

func (s *CommonTestSuite) TestDetectRFC_5424() {
	p, err := DetectRFC(
		[]byte("<165>1 2003-10-11T22:14:15.003Z ..."),
	)

	s.Require().Nil(err)
	s.Require().Equal(p, RFC(RFC_5424))
}

func (s *CommonTestSuite) TestFindNextSpace() {
	testCases := []struct {
		description       string
		input             []byte
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "no space",
			input:             []byte("aaaaaa"),
			expectedCursorPos: 0,
			expectedErr:       ErrNoSpace,
		},
		{
			description:       "space found",
			input:             []byte("foo bar baz"),
			expectedCursorPos: 4,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		obtained, err := FindNextSpace(
			tc.input, 0, len(tc.input),
		)

		s.Require().Equal(
			obtained, tc.expectedCursorPos, tc.description,
		)

		s.Require().Equal(
			err, tc.expectedErr, tc.description,
		)
	}
}

func BenchmarkParsePriority(b *testing.B) {
	buff := []byte("<190>")
	var start int
	l := len(buff)

	for i := 0; i < b.N; i++ {
		start = 0
		_, err := ParsePriority(buff, &start, l)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkParseVersion(b *testing.B) {
	buff := []byte("<123>1")
	start := 5
	l := len(buff)

	for i := 0; i < b.N; i++ {
		start = 0
		_, err := ParseVersion(buff, &start, l)
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkDetectRFC(b *testing.B) {
	buff := []byte("<165>1 2003-10-11T22:14:15.003Z ...")

	for i := 0; i < b.N; i++ {
		_, err := DetectRFC(buff)
		if err != nil {
			panic(err)
		}
	}
}

func TestCommonTestSuite(t *testing.T) {
	suite.Run(
		t, new(CommonTestSuite),
	)
}
