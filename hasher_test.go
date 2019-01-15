package hasher

import "testing"

func TestHash(t *testing.T) {
	hasher := New()
	testCases := []struct {
		name      string
		password1 string
		password2 string
		match     bool
	}{
		{
			name:      "All good",
			password1: "testpass",
			password2: "testpass",
			match:     true,
		},
		{
			name:      "Invalid password",
			password1: "testpass",
			password2: "not-testpass",
			match:     false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			hashed, err := hasher.Hash(tt.password1)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			match, err := hasher.ComparePasswordAndHash(tt.password2, hashed)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if match != tt.match {
				t.Errorf("passwords doesn't match when they should")
				return
			}
		})
	}
}

func TestHasherWithInvalidHash(t *testing.T) {
	t.Run("Invalid hash", func(t *testing.T) {
		// hashed password "testpass"
		// removed version from hash
		invHash := "argon2&m=65536,t=3,p=2&BZS21nYXiQ6mQ732+f3FtA&sgIRBy9MNL6Cdp/+o2qJKaZ7e2TRiejpifO3+MZ3IjE"

		hasher := New()

		_, err := hasher.ComparePasswordAndHash("testpass", invHash)
		if err != ErrInvalidHash {
			t.Errorf("exp error: %v\ngot error: %v", ErrInvalidHash, err)
			return
		}
	})
}

func TestHasherWithInvalidVersion(t *testing.T) {
	t.Run("Invalid argon2 version", func(t *testing.T) {
		// hashed password "testpass" with version 19
		// changed version from 19 to 21 in hash
		invHash := "argon2&v=21&m=65536,t=3,p=2&BZS21nYXiQ6mQ732+f3FtA&sgIRBy9MNL6Cdp/+o2qJKaZ7e2TRiejpifO3+MZ3IjE"

		hasher := New()

		_, err := hasher.ComparePasswordAndHash("testpass", invHash)
		if err != ErrInvalidArgonVersion {
			t.Errorf("exp error: %v\ngot error: %v", ErrInvalidHash, err)
			return
		}
	})
}
