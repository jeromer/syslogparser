package parsercommon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePriority(t *testing.T) {
	testCases := []struct {
		description       string
		input             []byte
		expectedPri       *Priority
		expectedCursorPos int
		expectedErr       error
	}{
		{
			description:       "empty priority",
			input:             []byte(""),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityEmpty,
		},
		{
			description:       "no start",
			input:             []byte("7>"),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNoStart,
		},
		{
			description:       "no end",
			input:             []byte("<77"),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNoEnd,
		},
		{
			description:       "too short",
			input:             []byte("<>"),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityTooShort,
		},
		{
			description:       "too long",
			input:             []byte("<1233>"),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityTooLong,
		},
		{
			description:       "no digits",
			input:             []byte("<7a8>"),
			expectedPri:       nil,
			expectedCursorPos: 0,
			expectedErr:       ErrPriorityNonDigit,
		},
		{
			description:       "all good",
			input:             []byte("<190>"),
			expectedPri:       NewPriority(190),
			expectedCursorPos: 5,
			expectedErr:       nil,
		},
	}

	for _, tc := range testCases {
		cursor := 0

		obtained, err := ParsePriority(
			tc.input, &cursor, len(tc.input),
		)

		require.Equal(
			t, tc.expectedPri, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)
	}
}

func TestNewPriority(t *testing.T) {
	require.Equal(
		t,
		&Priority{
			P: 165,
			F: Facility{Value: 20},
			S: Severity{Value: 5},
		},
		NewPriority(165),
	)
}

func TestParseVersion(t *testing.T) {
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

		require.Equal(
			t, tc.expectedVersion, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
		)
	}
}

func TestParseHostname(t *testing.T) {
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

		require.Equal(
			t, tc.expectedHostname, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedCursorPos, cursor, tc.description,
		)

		require.Nil(
			t, err,
		)
	}
}

func TestFindNextSpace(t *testing.T) {
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

		require.Equal(
			t, tc.expectedCursorPos, obtained, tc.description,
		)

		require.Equal(
			t, tc.expectedErr, err, tc.description,
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
