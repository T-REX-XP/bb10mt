package connect

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

func HashPassword(ctx context.Context, password string, salt, challenge []byte, iterations uint32) ([]byte, error) {
	if iterations == 0 || iterations > 1000000 || len(password) > 4096 || len(salt) > 4096 || len(challenge) > 4096 {
		return nil, fmt.Errorf("invalid password challenge parameters")
	}
	data := []byte(password)
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			data = append(append([]byte{}, challenge...), data...)
		}
		for count := uint32(0); count < iterations; count++ {
			if count%256 == 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				default:
				}
			}
			h := sha512.New()
			var index [4]byte
			binary.LittleEndian.PutUint32(index[:], count)
			h.Write(index[:])
			h.Write(salt)
			h.Write(data)
			data = h.Sum(nil)
		}
	}
	return data, nil
}

// PublicKey validates the authorized_keys RSA encoding before sending it. It
// accepts only one public-key line and never logs its contents.
func PublicKey(text []byte) (string, error) {
	line := strings.TrimSpace(string(text))
	if strings.ContainsAny(line, "\r\n") || len(line) > 16384 {
		return "", fmt.Errorf("expected one RSA public-key line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-rsa" {
		return "", fmt.Errorf("expected an ssh-rsa public key, not a private key")
	}
	b, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("invalid public-key encoding")
	}
	var items [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return "", fmt.Errorf("truncated RSA public key")
		}
		n := uint64(binary.BigEndian.Uint32(b))
		b = b[4:]
		if n > uint64(len(b)) {
			return "", fmt.Errorf("invalid RSA public-key length")
		}
		items = append(items, b[:n])
		b = b[n:]
	}
	if len(items) != 3 || string(items[0]) != "ssh-rsa" || len(items[1]) == 0 || len(items[1]) > 4 || len(items[2]) < 128 || len(items[2]) > 1025 {
		return "", fmt.Errorf("invalid RSA public-key fields")
	}
	return line, nil
}

type Options struct {
	Password, PublicKey string
	Timeout             time.Duration
	Log                 io.Writer
	Ready               func()
}
type session struct {
	conn    net.Conn
	options Options
	writeMu sync.Mutex
	key     []byte
	private *rsa.PrivateKey
}

func (s *session) send(code uint16, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.options.Timeout)); err != nil {
		return err
	}
	return WriteFrame(s.conn, code, data)
}
func (s *session) encrypted(code uint16, plain []byte) error {
	data, err := encrypt(s.key, plain)
	if err != nil {
		return err
	}
	return s.send(code, data)
}
func (s *session) challenge(data []byte) error {
	// Offsets are relative to the frame payload, not a TCP read buffer.
	if len(data) < 24 {
		return fmt.Errorf("truncated encrypted challenge")
	}
	source, container := int(binary.LittleEndian.Uint16(data[4:])), int(binary.LittleEndian.Uint16(data[10:]))
	if source > len(data)-24 || container != 128 || container > len(data)-24-source {
		return fmt.Errorf("invalid RSA challenge bounds")
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, s.private, data[24+source:24+source+container])
	if err != nil {
		return fmt.Errorf("RSA challenge decryption failed")
	}
	if len(plain) < 30 {
		return fmt.Errorf("short server challenge")
	}
	items := map[byte][]byte{}
	for b := plain; len(b) > 0; {
		if len(b) < 2 || int(b[0]) > len(b)-2 {
			return fmt.Errorf("invalid server challenge TLV")
		}
		n, id := int(b[0]), b[1]
		if _, ok := items[id]; ok {
			return fmt.Errorf("duplicate server challenge item")
		}
		items[id] = b[2 : 2+n]
		b = b[2+n:]
	}
	if len(items[2]) != 16 {
		return fmt.Errorf("unsupported server AES session-key size")
	}
	s.key = append([]byte{}, items[2]...)
	reply := append(append([]byte{}, plain[:30]...), 3, 4, 118, 131, 1)
	hash := sha1.Sum(reply)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.private, crypto.SHA1, hash[:])
	if err != nil {
		return err
	}
	payload := make([]byte, 6+len(reply)+len(signature))
	binary.BigEndian.PutUint16(payload, uint16(len(payload)-2))
	binary.BigEndian.PutUint16(payload[2:], uint16(len(reply)))
	binary.BigEndian.PutUint16(payload[4:], uint16(len(signature)))
	copy(payload[6:], reply)
	copy(payload[6+len(reply):], signature)
	return s.encrypted(5, payload)
}
func (s *session) authenticate(ctx context.Context, data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("truncated password challenge")
	}
	iterations := binary.BigEndian.Uint32(data[4:])
	saltLen, challengeLen := int(binary.BigEndian.Uint16(data[8:])), int(binary.BigEndian.Uint16(data[10:]))
	if saltLen > len(data)-12 || challengeLen > len(data)-12-saltLen {
		return fmt.Errorf("invalid password challenge bounds")
	}
	digest, err := HashPassword(ctx, s.options.Password, data[12:12+saltLen], data[12+saltLen:12+saltLen+challengeLen], iterations)
	if err != nil {
		return err
	}
	text := strings.ToUpper(hex.EncodeToString(digest))
	payload := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(payload, uint16(len(text)))
	copy(payload[2:], text)
	return s.encrypted(10, payload)
}
func (s *session) sendKey() error {
	key := []byte(s.options.PublicKey)
	b := make([]byte, 2+len(key))
	binary.BigEndian.PutUint16(b, uint16(len(key)))
	copy(b[2:], key)
	return s.encrypted(7, b)
}

// Run owns and closes the connection. It stops on explicit feedback failures,
// malformed/out-of-order frames, timeouts or cancellation; it never retries a
// password. Synthetic transcript tests do not establish handset acceptance.
func Run(ctx context.Context, conn net.Conn, options Options) error {
	defer conn.Close()
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	if options.Log == nil {
		options.Log = io.Discard
	}
	key, err := PublicKey([]byte(options.PublicKey))
	if err != nil {
		return err
	}
	options.PublicKey = key
	s := &session{conn: conn, options: options}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	if err = s.send(1, nil); err != nil {
		return err
	}
	state := 0
	for {
		if err = conn.SetReadDeadline(time.Now().Add(options.Timeout)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		frame, err := ReadFrame(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		switch frame.Code {
		case 2:
			if len(frame.Data) < 4 {
				return fmt.Errorf("truncated feedback")
			}
			code := binary.BigEndian.Uint16(frame.Data)
			n := int(binary.BigEndian.Uint16(frame.Data[2:]))
			if n > len(frame.Data)-4 {
				return fmt.Errorf("truncated feedback message")
			}
			if code != 0 && !(code == 17 && state == 3) {
				return fmt.Errorf("device rejected protocol step %d (feedback %d)", state, code)
			}
			switch state {
			case 0:
				s.private, err = rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					return err
				}
				mod := s.private.N.FillBytes(make([]byte, 128))
				data := make([]byte, 130)
				binary.BigEndian.PutUint16(data, 128)
				copy(data[2:], mod)
				err = s.send(3, data)
				state = 1
			case 2:
				err = s.send(8, nil)
				state = 3
			case 3:
				if code != 17 {
					return fmt.Errorf("unexpected password challenge acknowledgement")
				}
				err = s.sendKey()
				state = 5
			case 4:
				err = s.sendKey()
				state = 5
			case 5:
				err = s.send(11, nil)
				state = 6
			case 6:
				state = 7
				fmt.Fprintln(options.Log, "Connected; SSH public key accepted and services started.")
				if options.Ready != nil {
					options.Ready()
				}
				go func() {
					ticker := time.NewTicker(5 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							if s.send(6, nil) != nil {
								conn.Close()
								return
							}
						case <-done:
							return
						}
					}
				}()
			case 7:
			default:
				return fmt.Errorf("out-of-order feedback")
			}
		case 4:
			if state != 1 {
				return fmt.Errorf("out-of-order RSA challenge")
			}
			err = s.challenge(frame.Data)
			state = 2
		case 9:
			if state != 3 {
				return fmt.Errorf("out-of-order password challenge")
			}
			err = s.authenticate(ctx, frame.Data)
			state = 4
		case 12:
			return io.EOF
		default:
			return fmt.Errorf("unexpected network command %d", frame.Code)
		}
		if err != nil {
			return err
		}
	}
}
