package password

import "testing"

func TestSecureSalt(t *testing.T) {
	saltLen := []uint32{0, 1, 2, 4, 16, 32, 64}

	for _, l := range saltLen {
		_, err := SecureSalt(l)

		if err != nil {
			t.Error(err)
		}
	}
}
