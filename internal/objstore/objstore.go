// Package objstore reads and writes S3 objects, with conditional writes for checkpoints.
package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

var (
	ErrNotFound     = errors.New("object not found")
	ErrPrecondition = errors.New("conditional write rejected")
	ErrAccessDenied = errors.New("access denied")
)

const maxGetBytes = 256 << 20

type PutOptions struct {
	ContentType string
	Metadata    map[string]string
	// IfMatch makes the write succeed only while the object still has this ETag.
	IfMatch string
	// IfNoneMatch makes the write succeed only when the object does not exist yet.
	IfNoneMatch bool
}

type Store interface {
	Get(ctx context.Context, key string) (body []byte, etag string, err error)
	Put(ctx context.Context, key string, body []byte, opts PutOptions) (etag string, err error)
}

type S3 struct {
	Client   *s3.Client
	Bucket   string
	KMSKeyID string
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, string, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, "", classify(err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxGetBytes))
	if err != nil {
		return nil, "", fmt.Errorf("reading s3://%s/%s: %w", s.Bucket, key, err)
	}
	return body, aws.ToString(out.ETag), nil
}

func (s *S3) Put(ctx context.Context, key string, body []byte, opts PutOptions) (string, error) {
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		Metadata:      opts.Metadata,
	}
	if opts.ContentType != "" {
		in.ContentType = aws.String(opts.ContentType)
	}
	if opts.IfMatch != "" {
		in.IfMatch = aws.String(opts.IfMatch)
	}
	if opts.IfNoneMatch {
		in.IfNoneMatch = aws.String("*")
	}
	if s.KMSKeyID != "" {
		in.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = aws.String(s.KMSKeyID)
		in.BucketKeyEnabled = aws.Bool(true)
	}
	out, err := s.Client.PutObject(ctx, in)
	if err != nil {
		return "", classify(err)
	}
	return aws.ToString(out.ETag), nil
}

func classify(err error) error {
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchBucket":
			return fmt.Errorf("bucket does not exist: %w", err)
		case "NoSuchKey", "NotFound":
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		case "PreconditionFailed", "ConditionalRequestConflict":
			return fmt.Errorf("%w: %v", ErrPrecondition, err)
		case "AccessDenied", "Forbidden", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken",
			"KMS.AccessDeniedException", "KMS.DisabledException", "AllAccessDisabled":
			return fmt.Errorf("%w: %v", ErrAccessDenied, err)
		}
	}
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		switch re.HTTPStatusCode() {
		case 404:
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		case 409, 412:
			return fmt.Errorf("%w: %v", ErrPrecondition, err)
		case 401, 403:
			return fmt.Errorf("%w: %v", ErrAccessDenied, err)
		}
	}
	return err
}
