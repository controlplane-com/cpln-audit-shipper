package objstore

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
)

func TestClassifyMapsS3ErrorCodes(t *testing.T) {
	cases := map[string]error{
		"NoSuchKey":                  ErrNotFound,
		"NotFound":                   ErrNotFound,
		"PreconditionFailed":         ErrPrecondition,
		"ConditionalRequestConflict": ErrPrecondition,
		"AccessDenied":               ErrAccessDenied,
		"KMS.AccessDeniedException":  ErrAccessDenied,
		"ExpiredToken":               ErrAccessDenied,
	}
	for code, want := range cases {
		err := classify(&smithy.GenericAPIError{Code: code, Message: "m"})
		if !errors.Is(err, want) {
			t.Errorf("%s classified as %v, want %v", code, err, want)
		}
	}
	if got := classify(&smithy.GenericAPIError{Code: "NoSuchBucket"}); errors.Is(got, ErrNotFound) {
		t.Errorf("a missing bucket must not look like a missing checkpoint: %v", got)
	}
	other := &smithy.GenericAPIError{Code: "SlowDown"}
	if got := classify(other); errors.Is(got, ErrNotFound) || errors.Is(got, ErrPrecondition) || errors.Is(got, ErrAccessDenied) {
		t.Errorf("SlowDown classified as %v", got)
	}
}
