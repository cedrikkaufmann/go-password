package password

import "errors"

var (
  ErrUnknownAlgorithm = errors.New("unknown/unsupported hashing algorithm")
  ErrVersionMismatch = errors.New("algorithm version mismatch")
  ErrEncodingFormat = errors.New("wrong encoding format")
)
