package password

import "crypto/rand"

// SecureSalt generates a secure salt with given length using crypto/rand package
// returns salt or error
func SecureSalt(length uint32) ([]byte, error) {
  salt := make([]byte, length)
  _, err := rand.Read(salt)

  if err != nil {
    return nil, err
  }

  return salt, nil
}
