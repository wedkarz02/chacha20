# ChaCha20

[![GitHub](https://img.shields.io/github/license/wedkarz02/chacha20)](https://github.com/wedkarz02/chacha20/blob/main/LICENSE)

Go implementation of the ChaCha20 cipher algorithm. \
It was coded referencing [RFC8439](https://datatracker.ietf.org/doc/html/rfc8439) and tested with it's test vectors. \
Current release provides access to unverified encryption and decryption only. AEAD implemented with the Poly1305 MAC algorithm is planned for future releases.
<br /><br />
As always, I do not recommend using this package for anything that needs actual security.

# Requirements
 * [Go v1.20+](https://go.dev/dl/)
 * [Linux OS (preferably)](https://ubuntu.com/download)

# Quick Setup
If you haven't created a go module for your project, you can do that with the ``go mod`` command:
```bash
$ go mod init [project name]
```
To include this package in your project use the ``go get`` command:
```bash
$ go get -u github.com/wedkarz02/chacha20
```
# Example
```go
// main.go
package main

import (
    "fmt"
    "log"

    "github.com/wedkarz02/chacha20"
)

func main() {
    key := []byte("Super secret key")
    message := []byte("ChaCha20 encryption is really cool and also fast!")

    // Cipher object initialization.
    cipher, err := chacha20.NewCipher(key)

    // It is strongly recommended to wipe the key from memory at the end.
    defer cipher.ClearKey()

    // Make sure to check for any errors.
    if err != nil {
        log.Fatalf("Cipher init error: %v\n", err)
    }

    // Encrypting the plainText.
    cipherText, err := cipher.Encrypt(plainText)

    // Make sure to check for any errors.
    if err != nil {
        log.Fatalf("Encryption error: %v\n", err)
    }

    // Printing the cipherText as bytes.
    for _, b := range cipherText {
        fmt.Printf("0x%02x ", b)
    }
}
```

You might also need to use the ``go mod tidy`` command to fetch necessary dependencies:
```bash
$ go mod tidy
```

For more examples, see [chacha20/examples](https://github.com/wedkarz02/chacha20/tree/main/examples).

# Testing
To test this package use the ``go test`` command from the root directory:
```bash
$ go test -v
```

# License
chacha20 is available under the MIT license. See the [LICENSE](https://github.com/wedkarz02/chacha20/blob/main/LICENSE) file for more info.
