package password

import (
  "encoding/base64"
  "fmt"
  "golang.org/x/crypto/argon2"
  "reflect"
  "strings"
)

type Argon2Algorithm uint8

const (
  AlgorithmArgon2id Argon2Algorithm = iota
  AlgorithmArgon2i
)

type Argon2Params struct {
  Algorithm Argon2Algorithm
  SaltLength uint32
  KeyLength uint32
  Time uint32
  Memory uint32
  Threads uint8
  Version int
}

// argon2AlgorithmToString converts the algorithm to its string representation
// returns algorithm as string or error
func argon2AlgorithmToString(alg Argon2Algorithm) (string, error) {
  switch alg {
  case AlgorithmArgon2id:
    return "argon2id", nil
  case AlgorithmArgon2i:
    return "argon2i", nil
  default:
    return "", ErrUnknownAlgorithm
  }
}

func argon2StringToAlgorithm(alg string) (Argon2Algorithm, error) {
  switch alg {
  case "argon2id":
    return AlgorithmArgon2id, nil
  case "argon2i":
    return AlgorithmArgon2i, nil
  default:
    return 0, ErrUnknownAlgorithm
  }
}

// HashArgon2 hashes a password using the Argon2 implementation
// returns the hashed key and salt or error
func HashArgon2(password string, p *Argon2Params) ([]byte, []byte, error) {
  // generate secure salt
  salt, err := SecureSalt(p.SaltLength)

  if err != nil {
    return nil, nil, err
  }

  // get algorithm string
  alg, err := argon2AlgorithmToString(p.Algorithm)

  if err != nil {
    return nil, nil, err
  }

  // generate hash
  var key []byte

  if alg == "argon2id" {
    key = argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLength)
  } else {
    key = argon2.Key([]byte(password),  salt, p.Time, p.Memory, p.Threads, p.KeyLength)
  }

  // return hash and salt
  return key, salt, nil
}

// HashArgon2Raw generates a hash using the specified salt and params using argon2
//
// This function doesn't generate its own secure salt
//
// returns hash or error
func HashArgon2Raw(clear []byte, salt []byte, p *Argon2Params) ([]byte, error) {
  // get algorithm string
  alg, err := argon2AlgorithmToString(p.Algorithm)

  if err != nil {
    return nil, err
  }

  // generate hash
  var key []byte

  if alg == "argon2id" {
    key = argon2.IDKey(clear, salt, p.Time, p.Memory, p.Threads, p.KeyLength)
  } else {
    key = argon2.Key(clear,  salt, p.Time, p.Memory, p.Threads, p.KeyLength)
  }

  return key, nil
}

const argonEncFormat = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"

// VerifyArgon2 verifies a password and an encoded argon2 hash using the Argon2 implementation
// returns boolean or error
func VerifyArgon2(password string, encodedHash string) (bool, error) {
  // decode string
  decodedHash, decodedSalt, p, err := DecodeArgon2(encodedHash)

  if err != nil {
    return false, err
  }

  // version check
  if p.Version != argon2.Version {
    return false, ErrVersionMismatch
  }

  // generate hash with custom salt
  hash, err := HashArgon2Raw([]byte(password), decodedSalt, p)

  if err != nil {
    return false, nil
  }

  // check hash
  if reflect.DeepEqual(hash, decodedHash) {
    return true, nil
  } else {
    return false, nil
  }
}

// EncodeArgon2 encodes a given Argon2 hash and salt
// returns encoded hash or error
func EncodeArgon2(hash []byte, salt[]byte, p *Argon2Params) (string, error) {
  encAlg, err := argon2AlgorithmToString(p.Algorithm)

  if err != nil {
    return "", err
  }

  b64Hash := base64.RawStdEncoding.EncodeToString(hash)
  b64Salt := base64.RawStdEncoding.EncodeToString(salt)

  enc := fmt.Sprintf(argonEncFormat, encAlg, argon2.Version, p.Memory, p.Time, p.Threads, b64Salt, b64Hash)

  return enc, nil
}


func DecodeArgon2(enc string) ([]byte, []byte, *Argon2Params, error) {
  // parse encoded hash
  vals := strings.Split(enc, "$")

  if len(vals) != 6 {
    return nil, nil, nil, ErrEncodingFormat
  }

  var p Argon2Params

  // read argon2 algorithm
  alg, err := argon2StringToAlgorithm(vals[1])

  if err != nil {
    return nil, nil, nil, err
  }

  p.Algorithm = alg

  // read argon2 version
  _, err = fmt.Sscanf(vals[2], "v=%d", &p.Version)

  if err != nil {
    return nil, nil, nil, err
  }

  // read argon2 key derivation settings
  _, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads)

  if err != nil {
    return nil, nil, nil, err
  }

  // decode base64 salt string
  salt, err := base64.RawStdEncoding.DecodeString(vals[4])

  if err != nil {
    return nil, nil, nil, err
  }

  // set salt length
  p.SaltLength = uint32(len(salt))

  // decode base64 hash string
  hash, err := base64.RawStdEncoding.DecodeString(vals[5])

  if err != nil {
    return nil, nil, nil, err
  }

  // set key length
  p.KeyLength = uint32(len(hash))

  return hash, salt, &p, nil
}
