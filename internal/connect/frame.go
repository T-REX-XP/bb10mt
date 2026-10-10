// Package connect implements the BB10 network development-service protocol.
// Legacy RSA1024/SHA1/AES-CBC parameters are required by that wire protocol.
package connect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type Frame struct {
	Code uint16
	Data []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var header [6]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return f, err
	}
	size := int(binary.BigEndian.Uint16(header[:2]))
	if size < 6 || binary.BigEndian.Uint16(header[2:4]) != 2 {
		return f, fmt.Errorf("invalid BB10 network frame header")
	}
	f.Code = binary.BigEndian.Uint16(header[4:])
	f.Data = make([]byte, size-6)
	_, err := io.ReadFull(r, f.Data)
	return f, err
}
func WriteFrame(w io.Writer, code uint16, data []byte) error {
	if len(data) > 65529 {
		return fmt.Errorf("network frame too large")
	}
	b := make([]byte, len(data)+6)
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	binary.BigEndian.PutUint16(b[2:], 2)
	binary.BigEndian.PutUint16(b[4:], code)
	copy(b[6:], data)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	if len(plain) > 65503 || len(plain)+padding > 65503 {
		return nil, fmt.Errorf("encrypted frame too large")
	}
	data := make([]byte, len(plain)+padding)
	copy(data, plain)
	for i := len(plain); i < len(data); i++ {
		data[i] = byte(padding)
	}
	packet := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(packet, uint16(len(data)))
	binary.BigEndian.PutUint16(packet[2:], uint16(len(plain)))
	if _, err = io.ReadFull(rand.Reader, packet[4:20]); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, packet[4:20]).CryptBlocks(packet[20:], data)
	return packet, nil
}
