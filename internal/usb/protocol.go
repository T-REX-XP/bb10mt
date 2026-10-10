// Package usb isolates the BB10 channel protocol from its libusb adapter.
package usb

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/bb10root/bb10mt/internal/connect"
)

type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
	Close() error
}
type Protocol struct {
	IO       Transport
	Mode     byte
	sequence [2]uint16
}

func NewProtocol(t Transport) *Protocol { return &Protocol{IO: t, Mode: 0xff} }
func Outer(channel uint16, data []byte) ([]byte, error) {
	if channel > 2 || len(data) > 65531 {
		return nil, fmt.Errorf("invalid USB channel/frame size")
	}
	b := make([]byte, len(data)+4)
	binary.LittleEndian.PutUint16(b, channel)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], data)
	return b, nil
}
func ParseOuter(b []byte) (uint16, []byte, error) {
	if len(b) < 4 || len(b) > 65535 || int(binary.LittleEndian.Uint16(b[2:])) != len(b) || binary.LittleEndian.Uint16(b) > 2 {
		return 0, nil, fmt.Errorf("invalid USB outer frame")
	}
	return binary.LittleEndian.Uint16(b), b[4:], nil
}
func (p *Protocol) send(channel uint16, data []byte) error {
	b, err := Outer(channel, data)
	if err != nil {
		return err
	}
	return p.IO.Send(b)
}
func (p *Protocol) receive() (uint16, []byte, error) {
	b, err := p.IO.Receive()
	if err != nil {
		return 0, nil, err
	}
	return ParseOuter(b)
}
func (p *Protocol) ack() error {
	channel, b, err := p.receive()
	if err != nil {
		return err
	}
	// Legacy transports use an extra acknowledgement. Validate known framing
	// and any available CRC; its undocumented payload is not used as a status.
	if len(b) == 0 {
		return nil
	}
	if channel == 2 {
		_, _, err = parseChannel2(b)
		return err
	}
	if channel == 1 {
		_, _, err = parseChannel1(b)
		return err
	}
	if len(b) != 4 {
		return fmt.Errorf("invalid channel-0 acknowledgement")
	}
	return nil
}
func (p *Protocol) Channel0(command byte, data []byte) (byte, []byte, error) {
	b := make([]byte, 4+len(data))
	b[0] = command
	b[1] = p.Mode
	binary.BigEndian.PutUint16(b[2:], p.sequence[0])
	copy(b[4:], data)
	if err := p.send(0, b); err != nil {
		return 0, nil, err
	}
	channel, response, err := p.receive()
	if err != nil {
		return 0, nil, err
	}
	if channel != 0 || len(response) < 4 {
		return 0, nil, fmt.Errorf("invalid channel-0 response")
	}
	if binary.BigEndian.Uint16(response[2:]) != p.sequence[0] {
		return 0, nil, fmt.Errorf("channel-0 sequence mismatch")
	}
	p.sequence[0]++
	p.Mode = response[1]
	return response[0], response[4:], nil
}
func parseChannel1(b []byte) (uint16, []byte, error) {
	if len(b) < 10 || int(binary.LittleEndian.Uint32(b[4:])) != len(b) || crc32.ChecksumIEEE(b[4:]) != binary.LittleEndian.Uint32(b) {
		return 0, nil, fmt.Errorf("channel-1 length/CRC mismatch")
	}
	return binary.LittleEndian.Uint16(b[8:]), b[10:], nil
}
func (p *Protocol) Channel1(data []byte) ([]byte, error) {
	b := make([]byte, 10+len(data))
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[8:], p.sequence[1])
	copy(b[10:], data)
	binary.LittleEndian.PutUint32(b, crc32.ChecksumIEEE(b[4:]))
	if err := p.send(1, b); err != nil {
		return nil, err
	}
	channel, response, err := p.receive()
	if err != nil {
		return nil, err
	}
	if channel != 1 {
		return nil, fmt.Errorf("unexpected USB response channel")
	}
	sequence, payload, err := parseChannel1(response)
	if err != nil {
		return nil, err
	}
	if sequence != p.sequence[1] {
		return nil, fmt.Errorf("channel-1 sequence mismatch")
	}
	p.sequence[1]++
	if err = p.ack(); err != nil {
		return nil, err
	}
	return payload, nil
}
func channel2(command uint16, data []byte) []byte {
	b := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:], command)
	copy(b[4:], data)
	binary.LittleEndian.PutUint32(b[len(b)-4:], crc32.ChecksumIEEE(b[:len(b)-4]))
	return b
}
func parseChannel2(b []byte) (uint16, []byte, error) {
	if len(b) < 8 || int(binary.LittleEndian.Uint16(b)) != len(b) || crc32.ChecksumIEEE(b[:len(b)-4]) != binary.LittleEndian.Uint32(b[len(b)-4:]) {
		return 0, nil, fmt.Errorf("channel-2 length/CRC mismatch")
	}
	command := binary.LittleEndian.Uint16(b[2:])
	if command == 0x15 {
		return command, nil, fmt.Errorf("device rejected channel-2 command")
	}
	return command, b[4 : len(b)-4], nil
}
func (p *Protocol) Channel2(command uint16, data []byte, expected ...uint16) ([]byte, error) {
	if len(data) > 65523 {
		return nil, fmt.Errorf("channel-2 payload too large")
	}
	if err := p.send(2, channel2(command, data)); err != nil {
		return nil, err
	}
	channel, response, err := p.receive()
	if err != nil {
		return nil, err
	}
	if channel != 2 {
		return nil, fmt.Errorf("unexpected USB response channel")
	}
	code, payload, err := parseChannel2(response)
	if err != nil {
		return nil, err
	}
	match := len(expected) == 0
	for _, want := range expected {
		if want == code {
			match = true
		}
	}
	if !match {
		return nil, fmt.Errorf("USB command 0x%04x returned 0x%04x", command, code)
	}
	if err = p.ack(); err != nil {
		return nil, err
	}
	return payload, nil
}
func (p *Protocol) SetMode(mode byte) error {
	names := []string{"RIM REINIT", "RIM-BootLoader", "RIM-RAMLoader", "RIM UPL", "RIM-BootNUKE"}
	if int(mode) >= len(names) {
		return fmt.Errorf("invalid boot mode")
	}
	b := make([]byte, 17)
	copy(b, names[mode])
	b[16] = 1
	command, _, err := p.Channel0(7, b)
	if err != nil {
		return err
	}
	if command != 8 {
		return fmt.Errorf("device rejected boot mode")
	}
	return nil
}
func (p *Protocol) Password(ctx context.Context, password string) error {
	command, data, err := p.Channel0(0xa, nil)
	if err != nil {
		return err
	}
	if command == 0x10 {
		return p.ack()
	}
	if command != 0xe || len(data) < 24 {
		return fmt.Errorf("invalid USB password challenge")
	}
	if password == "" {
		return fmt.Errorf("device requires its explicit password; no password attempted")
	}
	if data[0] >= data[1] || int(data[1])-int(data[0]) <= 2 {
		return fmt.Errorf("password attempt budget too low")
	}
	digest, err := connect.HashPassword(ctx, password, data[12:20], data[4:8], binary.LittleEndian.Uint32(data[20:]))
	if err != nil {
		return err
	}
	b := append([]byte{0, 0, 0x40, 0}, digest...)
	command, _, err = p.Channel0(0xf, b)
	if err != nil {
		return err
	}
	if command != 0x10 {
		return fmt.Errorf("device rejected password; no retry attempted")
	}
	return p.ack()
}
func (p *Protocol) Switch() error {
	if err := p.send(1, []byte{6, 6}); err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		if _, _, err := p.receive(); err != nil {
			return err
		}
	}
	p.sequence[1] = 0
	return nil
}
func (p *Protocol) BootCommand(command uint16, data []byte) ([]byte, error) {
	b := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(b, command)
	copy(b[2:], data)
	return p.Channel1(b)
}
func (p *Protocol) Load(ctx context.Context, address uint32, data []byte, chunk int) error {
	if len(data) == 0 || uint64(address)+uint64(len(data)) > 1<<32 || chunk < 1 || chunk > 2044 {
		return fmt.Errorf("invalid RAM loader extent/chunk")
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, address)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	if _, err := p.BootCommand(0xf009, b); err != nil {
		return err
	}
	for at := 0; at < len(data); {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n := min(chunk, len(data)-at)
		b := make([]byte, 8+n)
		binary.LittleEndian.PutUint32(b, address+uint32(at))
		binary.LittleEndian.PutUint32(b[4:], uint32(n))
		copy(b[8:], data[at:at+n])
		if _, err := p.BootCommand(0xf004, b); err != nil {
			return err
		}
		at += n
	}
	if _, err := p.BootCommand(0xf00a, nil); err != nil {
		return err
	}
	return nil
}
func (p *Protocol) Run(address uint32) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, address)
	if _, err := p.BootCommand(0xf005, b); err != nil {
		return err
	}
	return p.ack()
}
func (p *Protocol) Nuke() error {
	if _, err := p.BootCommand(0xf008, nil); err != nil {
		return err
	}
	return p.ack()
}
func (p *Protocol) DrainLog() error {
	for i := 0; i < 4096; i++ {
		if err := p.send(2, channel2(0xb0, make([]byte, 8))); err != nil {
			return err
		}
		channel, b, err := p.receive()
		if err != nil {
			return err
		}
		if channel != 2 {
			return fmt.Errorf("unexpected log channel")
		}
		code, _, err := parseChannel2(b)
		if err != nil {
			return err
		}
		if err = p.ack(); err != nil {
			return err
		}
		if code == 0xd0 {
			return nil
		}
		if code != 0xb5 {
			return fmt.Errorf("unexpected log response")
		}
	}
	return fmt.Errorf("device log did not terminate")
}
