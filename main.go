package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

var (
	errInvalidKeyPair = errors.New("Error happen while decrypt the message. It seem like the public/private key pair is invalid.")
)

// generateSharedKey generate shared key that used by OpenAfterPrecomputation
// and SealAfterPrecomputation to speed up processing when using the same pair of keys repeatedly.
func generateSharedKey(priv, pub *[32]byte) *[32]byte {
	var sharedKey [32]byte
	box.Precompute(&sharedKey, pub, priv)
	return &sharedKey
}

// A SecureReader represents secure reader with pre-defined key and specified io.Reader
type SecureReader struct {
	// key is a shared key that used to decrypt the message
	key    *[32]byte
	reader io.Reader
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	sharedKey := generateSharedKey(priv, pub)
	return SecureReader{sharedKey, r}
}

// Read reads decrypted message into p.
// On return, n == len(dm) if and only if err == nil.
// Where dm is a decrypted message.
func (r SecureReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err != nil {
		return n, err
	}
	em := bytes.Trim(p, "\x00")
	var nonce [24]byte
	copy(nonce[:], em)
	if dm, ok := box.OpenAfterPrecomputation(nil, em[24:], &nonce, r.key); ok {
		n = copy(p, dm[:])
		return n, nil
	}
	return -1, errInvalidKeyPair
}

// A SecureWriter represents secure writer with pre-defined key and specified io.Writer
type SecureWriter struct {
	// key is a shared key that used to encrypt the message
	key    *[32]byte
	writer io.Writer
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	sharedKey := generateSharedKey(priv, pub)
	return SecureWriter{sharedKey, w}
}

// Write writes len(m) bytes to underlaying data stream. m is an encrypted message.
// On return, n == len(m) if and only if err == nil.
func (w SecureWriter) Write(p []byte) (n int, err error) {
	var nonce [24]byte
	n, err = rand.Read(nonce[:])
	if err != nil {
		return n, err
	}
	em := box.SealAfterPrecomputation(nonce[:], p, &nonce, w.key)
	n, err = w.writer.Write(em)
	if err != nil {
		return n, err
	}
	return len(em), nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
