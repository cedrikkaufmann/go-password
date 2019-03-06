# Go-Password
This package is used to simply hash a password using the argon2i or argon2id implementation. Despite this, the package is able to encode/decode a given hash, salt and params to a base64 string.

# Argon2 implementation
This package uses the default `golang.org/x/crypto/argon2` package.

# Usage
To generate a new hash of a password just use `func HashArgon2(password string, p *Argon2Params) ([]byte, []byte, error)`,whereas the first returned byte array is the actual hash and the second one the salt. 

If you want to use your own salt just use `func HashArgon2Raw(clear []byte, salt []byte, p *Argon2Params) ([]byte, error)`.

To encode a a given hash and salt use `func EncodeArgon2(hash []byte, salt []byte, p *Argon2Params) (string, error)` and for decoding `func DecodeArgon2(enc string) ([]byte, []byte, *Argon2Params, error)`.

The package also provides a verification mechanism to verfiy an encoded hash against a given passwort, to do so use `func VerifyArgon2(password string, encodedHash string) (bool, error)`

For params please have a look at the argon2 documentation and use the following struct.

```
type Argon2Params struct {
	Algorithm  Argon2Algorithm
	SaltLength uint32
	KeyLength  uint32
	Time       uint32
	Memory     uint32
	Threads    uint8
}
```

## Example

In this two examples, we provide a brief overview of how to use this package, to first create a new hash of a given passwort and in the second one we will show you how to verify a password.

Generate new hash:

```
user := "john@example.com"
passwort := "some_password_eg_from_webform"

params := &password.Argon2Params{
    Algorithm: password.AlgorithmArgon2id,
    SaltLength: 16,
    KeyLength: 32,
    Time: 3,
    Memory: 64*1024,
    Threads: 4,
}

hash, salt, err := password.HashArgon2(password, params)

if err != nil {
    panic(err)
}

enc, err := password.EncodeArgon2(hash, salt, params)

if err != nil {
    panic(err)
}

db.SaveHash(user, enc) // This is not part of the package, just and example usage of the encoded hash, for future authentication

```

Authenaticate user:

```
user := "john@example.com"
password := "some_password_eg_from_webform"

userHash := db.GetHash(user)

passwordValid, err := password.VerifyArgon2(password, enc)

if err != nil {
    panic(err)
}

if !passwordValid {
    // auth failed
    return
}

// auth pass
```

# License
MIT licensed 2019 Cedrik Kaufmann. See the LICENSE file for further details.