// TODO: pake encoding/binary package
package main

import (
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

// TODO: rombak semua baca smeua comment jangan ada yang salah

var (
	MAX_BUFFER = 1024
)

// A Box authenticates and encrypts messages using public-key cryptography.
type Box struct {
	PublicKey, PeersPublicKey, privateKey *[32]byte
}

// NewBox returns a new Box with random public and private keys.
// The peers public Key are nil by default.
// If failed generate random keys, it returns empty Box.
func NewBox() (bx Box, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return bx, err
	}
	bx = NewBoxKeys(pub, nil, priv)
	return bx, nil
}

// NewBoxKeys returns a new Box with specified public, peers public and private keys.
func NewBoxKeys(pub, peers, priv *[32]byte) Box {
	return Box{pub, peers, priv}
}

// Encrypt encrypts message m and returns encrypted message em if and only if err == nil.
func (b Box) Encrypt(m []byte) (em []byte, err error) {
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}
	em = box.Seal(nonce[:], m, &nonce, b.PeersPublicKey, b.privateKey)
	return em, nil
}

// Decrypt decrypts encrypted message em and return decrypted message m if and only if err == nil.
// If Box perform decryption using invalid key, it returns an error.
func (b Box) Decrypt(em []byte) (m []byte, err error) {
	var nonce [24]byte
	copy(nonce[:], em)
	if dm, ok := box.Open(nil, em[24:], &nonce, b.PeersPublicKey, b.privateKey); ok {
		return dm, nil
	}
	return nil, errors.New("Decrypt: cannot decrypt the message")
}

// A Reader represents a secure reader.
type Reader struct {
	bx Box       // box performs encryption and decryption
	rd io.Reader // underlying Reader
}

// NewReader returns a new Reader
func NewReader(rd io.Reader, bx Box) Reader {
	return Reader{bx, rd}
}

// Read reads decrypted message into p.
// On returns, n == len(dm) if and only if err == nil.
// Where dm is a decrypted message.
func (r Reader) Read(p []byte) (n int, err error) {
	n, err = r.rd.Read(p)
	if err != nil {
		return n, err
	}
	em := p[:n]
	dm, err := r.bx.Decrypt(em)
	if err != nil {
		return n, err
	}
	n = copy(p, dm[:])
	return n, nil
}

// A Writer represents a secure writer
type Writer struct {
	bx Box       // box performs encryption and decryption
	wr io.Writer // underlying Writer
}

// NewWriter returns a new Writer
func NewWriter(wr io.Writer, bx Box) Writer {
	return Writer{bx, wr}
}

// Write encrypts p and writes n bytes to underlaying data stream.
// On returns, n == len(em) if and only if err == nil.
func (w Writer) Write(p []byte) (n int, err error) {
	em, err := w.bx.Encrypt(p)
	if err != nil {
		return n, err
	}
	n, err = w.wr.Write(em)
	if err != nil {
		return n, err
	}
	return n, nil
}

// NewSecureReader instantiates a new Secure reader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	bx := NewBoxKeys(pub, pub, priv)
	rd := NewReader(r, bx)
	return rd
}

// NewSecureWriter instantiates a new Secure writer
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	bx := NewBoxKeys(pub, pub, priv)
	wr := NewWriter(w, bx)
	return wr
}

// A Client represents a secure client
type Client struct {
	rd Reader
	wr Writer
	cn net.Conn
}

// NewClient returns a new Client with specified Reader, Writer and underlying
// net.Conn.
func NewClient(rd Reader, wr Writer, cn net.Conn) Client {
	return Client{rd, wr, cn}
}

// Read reads decrypted message into p
func (c Client) Read(p []byte) (n int, err error) {
	n, err = c.rd.Read(p)
	return
}

// Write encrypt p and writes n bytes to underlying connection.
func (c Client) Write(p []byte) (n int, err error) {
	n, err = c.wr.Write(p)
	return
}

// Close close the connection
func (c Client) Close() error {
	return c.cn.Close()
}

// A Server represents a secure server
type Server struct {
	rd Reader
	wr Writer
	cn net.Conn
}

// NewServer returns a new Server
func NewServer(rd Reader, wr Writer, cn net.Conn) Server {
	return Server{rd, wr, cn}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("EClient: dial new connection %+v\n", client)

	// generate new box
	bx, err := NewBox()
	if err != nil {
		return nil, err
	}

	// Key exchange
	// receive key from server
	key := make([]byte, 32)
	n, err := conn.Read(key)
	// fmt.Printf("EClient: read %d bytes public key from the server p = %v\n", n, p)
	var peersKey [32]byte
	copy(peersKey[:], key[:n])
	bx.PeersPublicKey = &peersKey
	// send key to the server
	n, err = conn.Write(bx.PublicKey[:])
	if err != nil {
		return nil, err
	}
	// fmt.Printf("EClient transfer %d bytes key ti the server %v\n", n, pub[:])

	rd := NewReader(conn, bx)
	wr := NewWriter(conn, bx)
	c := NewClient(rd, wr, conn)
	return c, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	// fmt.Println("Server: executed\n")
	for {
		// fmt.Println("Server: wait client connected\n")
		client, err := l.Accept()
		// fmt.Printf("Server: client connected. client = %v\n", client)
		if err != nil {
			return err
		}
		// fmt.Printf("Server: Run handle go routine with client = %v\n\n", client)

		go handle(client)
	}
	return nil
}

func handle(client net.Conn) {
	bx, err := NewBox()
	if err != nil {
		fmt.Printf("Server: %v\n", err)
		return
	}

	// key exchange
	// fmt.Printf("Server: generate pub %v priv %v \n", pub, priv)
	n, err := client.Write(bx.PublicKey[:])
	if err != nil {
		fmt.Printf("Server: %v\n", err)
		return
	}
	// fmt.Printf("Server: send %d bytes public key to client. %v\n\n", n, pub[:])

	// get client public key
	key := make([]byte, 32)
	n, err = client.Read(key)
	if err != nil {
		fmt.Printf("Server: %v\n", err)
		return
	}
	// fmt.Printf("\nServer: read %d bytes public key from the client p = %v\n\n", n, p)
	var peersKey [32]byte
	copy(peersKey[:], key[:n])
	bx.PeersPublicKey = &peersKey

	rd := NewReader(client, bx)
	wr := NewWriter(client, bx)
	s := NewServer(rd, wr, client)
	for {
		// read and decrypt message
		p := make([]byte, MAX_BUFFER)
		n, err := s.rd.Read(p)
		if err != nil {
			if err == io.EOF {
				return
			}
			fmt.Printf("Server: %v\n", err)
			return
		}

		// encrypt and write to underlying connection
		n, err = s.wr.Write(p[:n])
		if err != nil {
			fmt.Printf("Server: %v\n", err)
			return
		}

	}
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
