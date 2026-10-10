package connect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func publicLine() string {
	var b bytes.Buffer
	for _, p := range [][]byte{[]byte("ssh-rsa"), {1, 0, 1}, append([]byte{0}, bytes.Repeat([]byte{0xa5}, 128)...)} {
		binary.Write(&b, binary.BigEndian, uint32(len(p)))
		b.Write(p)
	}
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(b.Bytes()) + " test"
}
func decryptPacket(key, packet []byte) ([]byte, error) {
	if len(packet) < 36 {
		return nil, fmt.Errorf("short encrypted packet")
	}
	n := int(binary.BigEndian.Uint16(packet))
	plainSize := int(binary.BigEndian.Uint16(packet[2:]))
	if n != len(packet)-20 || n%16 != 0 {
		return nil, fmt.Errorf("invalid packet length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := bytes.Clone(packet[20:])
	cipher.NewCBCDecrypter(block, packet[4:20]).CryptBlocks(out, out)
	padding := int(out[len(out)-1])
	if padding < 1 || padding > 16 || len(out)-padding != plainSize {
		return nil, fmt.Errorf("bad padding")
	}
	for _, b := range out[len(out)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return out[:plainSize], nil
}
func TestPasswordKnownVectorAndBounds(t *testing.T) {
	b, err := HashPassword(context.Background(), "example-password", []byte("salt"), []byte("challenge"), 3)
	if err != nil {
		t.Fatal(err)
	}
	const want = "68b2aa74185973245c1be1697b5e8439933e932129a16fd634410fa42936e3cca86c18e8864b46b7ad48f6b21af437c828a45583615a2ec056e05d847de5d6d0"
	if hex.EncodeToString(b) != want {
		t.Fatal(hex.EncodeToString(b))
	}
	if _, err = HashPassword(context.Background(), "", nil, nil, 0); err == nil {
		t.Fatal("zero iterations accepted")
	}
	if _, err = PublicKey([]byte("-----BEGIN PRIVATE KEY-----")); err == nil {
		t.Fatal("private key accepted")
	}
}
func TestFragmentedNetworkHandshake(t *testing.T) {
	client, server := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverError := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(5 * time.Second))
		expect := func(code uint16) (Frame, error) {
			f, err := ReadFrame(server)
			if err == nil && f.Code != code {
				err = fmt.Errorf("wanted %d got %d", code, f.Code)
			}
			return f, err
		}
		feedback := func() error { return WriteFrame(server, 2, make([]byte, 4)) }
		run := func() error {
			if _, err := expect(1); err != nil {
				return err
			}
			if err := feedback(); err != nil {
				return err
			}
			start, err := expect(3)
			if err != nil {
				return err
			}
			if len(start.Data) != 130 {
				return fmt.Errorf("bad RSA request")
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(start.Data[2:]), E: 65537}
			key := bytes.Repeat([]byte{0x42}, 16)
			challenge := append([]byte{4, 1, 1, 2, 3, 4, 16, 2}, key...)
			challenge = append(challenge, 4, 3, 5, 6, 7, 8)
			blob, err := rsa.EncryptPKCS1v15(rand.Reader, pub, challenge)
			if err != nil {
				return err
			}
			payload := make([]byte, 24+len(blob))
			binary.LittleEndian.PutUint16(payload[10:], uint16(len(blob)))
			copy(payload[24:], blob)
			var frame bytes.Buffer
			if err = WriteFrame(&frame, 4, payload); err != nil {
				return err
			}
			for _, b := range frame.Bytes() {
				if _, err = server.Write([]byte{b}); err != nil {
					return err
				}
			}
			reply, err := expect(5)
			if err != nil {
				return err
			}
			plain, err := decryptPacket(key, reply.Data)
			if err != nil {
				return err
			}
			replySize, signSize := int(binary.BigEndian.Uint16(plain[2:])), int(binary.BigEndian.Uint16(plain[4:]))
			if replySize != 35 || signSize != 128 || len(plain) != 6+replySize+signSize {
				return fmt.Errorf("invalid challenge reply")
			}
			hash := sha1.Sum(plain[6 : 6+replySize])
			if err = rsa.VerifyPKCS1v15(pub, crypto.SHA1, hash[:], plain[6+replySize:]); err != nil {
				return err
			}
			if err = feedback(); err != nil {
				return err
			}
			if _, err = expect(8); err != nil {
				return err
			}
			auth := make([]byte, 12)
			binary.BigEndian.PutUint32(auth[4:], 3)
			binary.BigEndian.PutUint16(auth[8:], 4)
			binary.BigEndian.PutUint16(auth[10:], 9)
			auth = append(auth, []byte("saltchallenge")...)
			if err = WriteFrame(server, 9, auth); err != nil {
				return err
			}
			response, err := expect(10)
			if err != nil {
				return err
			}
			plain, err = decryptPacket(key, response.Data)
			if err != nil {
				return err
			}
			digest, err := HashPassword(ctx, "example-password", []byte("salt"), []byte("challenge"), 3)
			if err != nil {
				return err
			}
			if string(plain[2:]) != strings.ToUpper(hex.EncodeToString(digest)) {
				return fmt.Errorf("password response differs")
			}
			if err = feedback(); err != nil {
				return err
			}
			ssh, err := expect(7)
			if err != nil {
				return err
			}
			plain, err = decryptPacket(key, ssh.Data)
			if err != nil {
				return err
			}
			if string(plain[2:]) != publicLine() {
				return fmt.Errorf("wrong SSH public key")
			}
			if err = feedback(); err != nil {
				return err
			}
			if _, err = expect(11); err != nil {
				return err
			}
			return feedback()
		}
		serverError <- run()
	}()
	err := Run(ctx, client, Options{Password: "example-password", PublicKey: publicLine(), Timeout: 5 * time.Second, Ready: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = <-serverError; err != nil {
		t.Fatal(err)
	}
}
func TestDeniedFeedbackStopsWithoutRetry(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { ReadFrame(server); WriteFrame(server, 2, []byte{0, 2, 0, 0}) }()
	if err := Run(ctx, client, Options{PublicKey: publicLine()}); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := server.Read(b[:]); err != io.EOF {
		t.Fatal("connection not closed", err)
	}
}
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 6, 0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, err := ReadFrame(bytes.NewReader(b))
		if err == nil {
			var encoded bytes.Buffer
			if err = WriteFrame(&encoded, frame.Code, frame.Data); err != nil {
				t.Fatal(err)
			}
		}
	})
}
