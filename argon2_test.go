package password

import "testing"

func TestArgon2idHashing(t *testing.T) {
	password := "HelloWorld"
	params := Argon2Params{
		Algorithm:  AlgorithmArgon2id,
		SaltLength: 12,
		KeyLength:  32,
		Time:       3,
		Memory:     12 * 1024,
		Threads:    4,
	}

	hashPasswd, salt, err := HashArgon2(password, &params)

	if err != nil {
		t.Error(err)
	}

	encoded, err := EncodeArgon2(hashPasswd, salt, &params)

	if err != nil {
		t.Error(err)
	}

	verify, err := VerifyArgon2(password, encoded)

	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("Hash verification failed")
	}
}

func TestArgon2iHashing(t *testing.T) {
	password := "HelloWorld"
	params := Argon2Params{
		Algorithm:  AlgorithmArgon2i,
		SaltLength: 12,
		KeyLength:  32,
		Time:       3,
		Memory:     64 * 1024,
		Threads:    4,
	}

	hashPasswd, salt, err := HashArgon2(password, &params)

	if err != nil {
		t.Error(err)
	}

	encoded, err := EncodeArgon2(hashPasswd, salt, &params)

	if err != nil {
		t.Error(err)
	}

	verify, err := VerifyArgon2(password, encoded)

	if err != nil {
		t.Error(err)
	}

	if !verify {
		t.Error("Hash verification failed")
	}
}

func TestConversionAlgorithm(t *testing.T) {
	algosInt := []Argon2Algorithm{0, 1, 2}
	algosString := []string{"argon2id", "argon2i", "_"}
	valid := []bool{true, true, false}

	for i, a := range algosInt {
		_, err := argon2AlgorithmToString(a)

		if valid[i] {
			if err != nil {
				t.Error(err)
			}
		} else {
			if err == nil {
				t.Errorf("conversion should have failed: %d", a)
			}
		}
	}

	for i, a := range algosString {
		_, err := argon2StringToAlgorithm(a)

		if valid[i] {
			if err != nil {
				t.Error(err)
			}
		} else {
			if err == nil {
				t.Errorf("conversion should have failed: %s", a)
			}
		}
	}
}
