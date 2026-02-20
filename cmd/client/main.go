package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"
)

func main() {
	srcIP := os.Args[1]
	dstIP := os.Args[2]
	dstPortStr := os.Args[3]
	dstPort, err := strconv.Atoi(dstPortStr)
	if err != nil {
		panic("Puerto inválido")
	}

	customData := []byte(fmt.Sprintf("Hello %02d", rand.Intn(100))) // 8 bytes + 2 chars = 10 bytes, cabe en el Timestamp Option (10 bytes)

	// Sin timezone para ahorrar bytes: 19 chars. Total data = 14+19 = 33 bytes ≤ 38 max
	//ts := time.Now().Format("2006-01-02T15:04:05")
	//customData := []byte("Hello ")
	//customData := []byte("12345678911234567892123456789313336-39") // 32 bytes + 19 chars = 51 bytes > 38 max, se truncará a 38

	err = sendCustomSYN(srcIP, dstIP, uint16(dstPort), customData)
	if err != nil {
		panic(err)
	}
}

// tcpChecksum calcula el checksum TCP usando el pseudo-header IPv4
func tcpChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpData))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpData)))
	copy(pseudo[12:], tcpData)

	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	if len(pseudo)%2 != 0 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildTCPSYN construye el header TCP manualmente para controlar exactamente el data offset
func buildTCPSYN(srcIP, dstIP net.IP, srcPort, dstPort uint16, opts []byte) []byte {
	tcpLen := 20 + len(opts)
	if tcpLen%4 != 0 {
		pad := 4 - (tcpLen % 4)
		opts = append(opts, make([]byte, pad)...)
		tcpLen = 20 + len(opts)
	}

	buf := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint32(buf[4:8], 1000)    // seq
	buf[12] = byte(tcpLen/4) << 4                 // data offset correcto
	buf[13] = 0x02                                // SYN flag
	binary.BigEndian.PutUint16(buf[14:16], 65535) // window
	copy(buf[20:], opts)

	cs := tcpChecksum(srcIP, dstIP, buf)
	binary.BigEndian.PutUint16(buf[16:18], cs)
	return buf
}

// tcpTimestampOption arma Kind=8 Length=10 + TSval(4) + TSecr(4)
func tcpTimestampOption(tsval, tsecr uint32) []byte {
	opt := make([]byte, 10)
	opt[0] = 8
	opt[1] = 10
	binary.BigEndian.PutUint32(opt[2:6], tsval)
	binary.BigEndian.PutUint32(opt[6:10], tsecr)
	return opt
}

// packUpTo8BytesInto2xU32: mete hasta 8 bytes en (tsval,tsecr) big-endian.
// Si data < 8, el resto se rellena con 0.
func packUpTo8BytesInto2xU32(data []byte) (uint32, uint32) {
	var b [8]byte
	copy(b[:], data)

	tsval := binary.BigEndian.Uint32(b[0:4])
	tsecr := binary.BigEndian.Uint32(b[4:8])
	return tsval, tsecr
}

func sendCustomSYN(srcIPStr, dstIPStr string, dstPort uint16, data []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Kind 8 (Timestamps): 10 bytes fijos
	tsval, tsecr := packUpTo8BytesInto2xU32(data)
	opts := tcpTimestampOption(tsval, tsecr)

	// Padding para alinear opciones a 4 bytes: añade 2 NOP (Kind=1)
	opts = append(opts, 1, 1)

	srcIP := net.ParseIP(srcIPStr).To4()
	dstIP := net.ParseIP(dstIPStr).To4()
	packet := buildTCPSYN(srcIP, dstIP, 44444, dstPort, opts)

	addr := syscall.SockaddrInet4{Port: int(dstPort)}
	copy(addr.Addr[:], dstIP)

	return syscall.Sendto(fd, packet, 0, &addr)
}
