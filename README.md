### Argon2 hasher client

#### What is Argon2?
Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg[...](https://en.wikipedia.org/wiki/Argon2)

### How to install:
`go get github.com/kerak19/hasher`

[![](https://godoc.org/github.com/nathany/looper?status.svg)](https://godoc.org/github.com/kerak19/hasher)


### How to use:
```go
package main

import "fmt"
import "github.com/kerak19/hasher"

func main() {
	hasher := hasher.Hasher{
		Params: hasher.Params{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}

	password := "testpass"
	hashed, err := hasher.Hash(password)
	if err != nil {
		panic(err)
	}

	fmt.Println(hashed) // argon2&v=19&m=65536,t=3,p=2&08wK3zQr0Ol2UeuofUBcFQ&4LAUwzG2NUROQTIBOdqaNbAYnseewi6Q+5/y6UUwD3Q

	fmt.Println(hasher.ComparePasswordAndHash("testpass", hashed)) // true, <nil>
}
```
  
Package is loosely based on https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
