package usb

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

type scripted struct {
	sent, responses [][]byte
	sendErr         error
}

func (s *scripted) Send(b []byte) error {
	s.sent = append(s.sent, append([]byte{}, b...))
	return s.sendErr
}
func (s *scripted) Receive() ([]byte, error) {
	if len(s.responses) == 0 {
		return nil, io.EOF
	}
	b := s.responses[0]
	s.responses = s.responses[1:]
	return b, nil
}
func (*scripted) Close() error { return nil }
func frame(ch uint16, b []byte) []byte {
	r, e := Outer(ch, b)
	if e != nil {
		panic(e)
	}
	return r
}
func c0(cmd byte, seq uint16, data []byte) []byte {
	b := append([]byte{cmd, 1, 0, 0}, data...)
	binary.BigEndian.PutUint16(b[2:], seq)
	return frame(0, b)
}
func c1(seq uint16, data []byte) []byte {
	b := make([]byte, 10+len(data))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[8:], seq)
	copy(b[10:], data)
	binary.LittleEndian.PutUint32(b, crc32.ChecksumIEEE(b[4:]))
	return frame(1, b)
}

func TestChannelsValidateFramingAndSequence(t *testing.T) {
	s := &scripted{responses: [][]byte{c0(6, 0, []byte("metrics")), c1(0, []byte("boot")), frame(1, nil), frame(2, channel2(0x4006, []byte("done"))), frame(2, nil)}}
	p := NewProtocol(s)
	if cmd, b, e := p.Channel0(5, []byte{1}); e != nil || cmd != 6 || string(b) != "metrics" {
		t.Fatal(cmd, string(b), e)
	}
	if b, e := p.BootCommand(0xf001, nil); e != nil || string(b) != "boot" {
		t.Fatal(string(b), e)
	}
	if b, e := p.Channel2(0x40c0, nil, 0x4006, 0x402e); e != nil || string(b) != "done" {
		t.Fatal(string(b), e)
	}
	if len(s.sent) != 3 || p.Mode != 1 || p.sequence != [2]uint16{1, 1} {
		t.Fatal(p, s)
	}
	for _, tc := range []struct {
		name     string
		response []byte
		call     func(*Protocol) error
	}{
		{"sequence0", c0(6, 1, nil), func(p *Protocol) error { _, _, e := p.Channel0(5, nil); return e }},
		{"sequence1", c1(1, nil), func(p *Protocol) error { _, e := p.Channel1(nil); return e }},
		{"wrong-channel", frame(0, nil), func(p *Protocol) error { _, e := p.Channel2(1, nil, 2); return e }},
		{"unexpected-status", frame(2, channel2(3, nil)), func(p *Protocol) error { _, e := p.Channel2(1, nil, 2); return e }},
		{"rejected", frame(2, channel2(0x15, nil)), func(p *Protocol) error { _, e := p.Channel2(1, nil); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scripted{responses: [][]byte{tc.response}}
			if e := tc.call(NewProtocol(s)); e == nil {
				t.Fatal("accepted malformed response")
			}
			if len(s.sent) != 1 {
				t.Fatal("retried")
			}
		})
	}
}
func TestCRCAndLengthRejectEveryTruncation(t *testing.T) {
	for _, b := range [][]byte{channel2(1, []byte("data")), c1(0, []byte("data"))[4:]} {
		parse := parseChannel2
		if len(b) > 0 && b[0] != byte(len(b)) {
			parse = parseChannel1
		}
		for n := 0; n < len(b); n++ {
			if _, _, e := parse(b[:n]); e == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		for n := range b {
			bad := bytes.Clone(b)
			bad[n] ^= 0x80
			if _, _, e := parse(bad); e == nil {
				t.Fatalf("accepted corruption %d", n)
			}
		}
	}
	if _, e := Outer(3, nil); e == nil {
		t.Fatal("channel")
	}
	if _, e := Outer(1, make([]byte, 65532)); e == nil {
		t.Fatal("oversize")
	}
	if _, e := NewProtocol(&scripted{}).Channel2(1, make([]byte, 65524)); e == nil {
		t.Fatal("oversize channel2")
	}
}
func TestPasswordDoesNotRetryOrGuess(t *testing.T) {
	challenge := make([]byte, 24)
	challenge[1] = 10
	binary.LittleEndian.PutUint32(challenge[20:], 1)
	for _, tc := range []struct {
		name, password string
		budget         byte
		responses      [][]byte
		want           string
		writes         int
	}{
		{"absent", "", 10, nil, "explicit password", 1},
		{"budget", "given", 2, nil, "budget", 1},
		{"rejected", "given", 10, [][]byte{c0(0xe, 1, challenge)}, "no retry", 2},
		{"accepted", "given", 10, [][]byte{c0(0x10, 1, nil), frame(0, nil)}, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(challenge)
			b[1] = tc.budget
			s := &scripted{responses: append([][]byte{c0(0xe, 0, b)}, tc.responses...)}
			e := NewProtocol(s).Password(context.Background(), tc.password)
			if tc.want == "" && e != nil || tc.want != "" && (e == nil || !strings.Contains(e.Error(), tc.want)) {
				t.Fatal(e)
			}
			if len(s.sent) != tc.writes {
				t.Fatal(len(s.sent))
			}
		})
	}
	s := &scripted{responses: [][]byte{c0(0x10, 0, nil), frame(0, nil)}}
	if e := NewProtocol(s).Password(context.Background(), ""); e != nil || len(s.sent) != 1 {
		t.Fatal(e)
	}
}
func TestLoaderChunksAndCancellation(t *testing.T) {
	data := []byte("0123456789")
	s := &scripted{}
	for seq := uint16(0); seq < 6; seq++ {
		s.responses = append(s.responses, c1(seq, nil), frame(1, nil))
	}
	p := NewProtocol(s)
	if e := p.Load(context.Background(), 0x80200000, data, 3); e != nil {
		t.Fatal(e)
	}
	var restored []byte
	for i, b := range s.sent {
		_, payload, e := parseChannel1(b[4:])
		if e != nil {
			t.Fatal(e)
		}
		cmd := binary.LittleEndian.Uint16(payload)
		switch {
		case i == 0:
			if cmd != 0xf009 || binary.LittleEndian.Uint32(payload[6:]) != 10 {
				t.Fatal(payload)
			}
		case i == 5:
			if cmd != 0xf00a {
				t.Fatal(payload)
			}
		default:
			if cmd != 0xf004 || binary.LittleEndian.Uint32(payload[2:]) != 0x80200000+uint32(len(restored)) || int(binary.LittleEndian.Uint32(payload[6:])) != len(payload)-10 {
				t.Fatal(payload)
			}
			restored = append(restored, payload[10:]...)
		}
	}
	if !bytes.Equal(data, restored) {
		t.Fatal(restored)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = &scripted{responses: [][]byte{c1(0, nil), frame(1, nil)}}
	if e := NewProtocol(s).Load(ctx, 1, data, 3); !errors.Is(e, context.Canceled) || len(s.sent) != 1 {
		t.Fatal(e)
	}
}
func TestAckFailureIsFatal(t *testing.T) {
	s := &scripted{responses: [][]byte{c1(0, nil), frame(2, []byte{1})}}
	if _, e := NewProtocol(s).Channel1(nil); e == nil {
		t.Fatal("bad ack accepted")
	}
	s = &scripted{sendErr: io.ErrClosedPipe}
	if _, _, e := NewProtocol(s).Channel0(1, nil); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal(e)
	}
}

func FuzzFrame(f *testing.F) {
	f.Add(frame(2, channel2(1, []byte("payload"))))
	f.Add(c1(0, nil))
	f.Add(c0(6, 0, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, p, e := ParseOuter(b)
		if e != nil {
			return
		}
		switch ch {
		case 1:
			parseChannel1(p)
		case 2:
			parseChannel2(p)
		}
	})
}
