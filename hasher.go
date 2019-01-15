package hasher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Hasher struct {
	Params Params
}

// New returns new Hasher with default parameters
func New() Hasher {
	return NewWithParams(Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})
}

// NewWithParams returns new hasher with custom parameters
func NewWithParams(p Params) Hasher {
	return Hasher{Params: p}
}

// sep is used for separating argon parameters in password hash
const sep = "&"

// b64Enc is used for encoding and decoding hash to/from base64 notation
var b64Enc = base64.RawStdEncoding

// Hash generates hash for provided password with additional informations. These informations contains version of argon2, memory, iterations, parallelism and salt. The final format is the following: "hasher&v=version&m=memory,t=iterations,p=parallelism&salt&passwordHash".
func (h Hasher) Hash(password string) (string, error) {
	salt, err := generateSalt(h.Params.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, h.Params.Iterations,
		h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)

	b64Salt := b64Enc.EncodeToString(salt)
	b64Hash := b64Enc.EncodeToString(hash)

	encPassword := fmt.Sprintf(
		"argon2%[1]sv=%[2]d%[1]sm=%[3]d,t=%[4]d,p=%[5]d%[1]s%[6]s%[1]s%[7]s",
		sep, argon2.Version, h.Params.Memory, h.Params.Iterations, h.Params.Parallelism,
		b64Salt, b64Hash)

	return encPassword, nil
}

// MustHash is same as Hash(), but panics if there's an error
func (h Hasher) MustHash(password string) string {
	encPassword, err := h.Hash(password)
	if err != nil {
		panic(err)
	}
	return encPassword
}

func generateSalt(l uint32) ([]byte, error) {
	salt := make([]byte, l)
	_, err := rand.Read(salt)
	return salt, err
}

// ComparePasswordAndHash compares provided password with hashed password. It'll return whether they match or not.
func (h Hasher) ComparePasswordAndHash(password, encHash string) (bool, error) {
	params, salt, hash, err := decodeHash(encHash)
	if err != nil {
		return false, err
	}

	hashForCompare := argon2.IDKey([]byte(password), salt, params.Iterations,
		params.Memory, params.Parallelism, params.KeyLength)

	return subtle.ConstantTimeCompare(hash, hashForCompare) == 1, nil
}

// MustComparePasswordAndHash is same as ComparePasswordAndHash(), but panics if there's an error
func (h Hasher) MustComparePasswordAndHash(password, encHash string) bool {
	match, err := h.ComparePasswordAndHash(password, encHash)
	if err != nil {
		panic(err)
	}
	return match
}

var ErrInvalidHash = errors.New("password hash is invalid")
var ErrInvalidArgonVersion = errors.New("argon2 version is incompatible with hash version")

func decodeHash(encHash string) (Params, []byte, []byte, error) {
	var params Params

	vals := strings.Split(encHash, sep)
	if len(vals) != 5 {
		return params, nil, nil, ErrInvalidHash
	}

	var v int
	_, err := fmt.Sscanf(vals[1], "v=%d", &v)
	if err != nil {
		return params, nil, nil, err
	}
	if v != argon2.Version {
		return params, nil, nil, ErrInvalidArgonVersion
	}

	_, err = fmt.Sscanf(vals[2], "m=%d,t=%d,p=%d",
		&params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return params, nil, nil, err
	}

	salt, err := b64Enc.DecodeString(vals[3])
	if err != nil {
		return params, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	hash, err := b64Enc.DecodeString(vals[4])
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, err
}
