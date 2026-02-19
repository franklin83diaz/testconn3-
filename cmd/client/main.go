package main

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	srcIP := os.Args[1]
	dstIP := os.Args[2]
	dstPortStr := os.Args[3]
	dstPort, err := strconv.Atoi(dstPortStr)
	if err != nil {
		panic("Puerto inválido")
	}

	// Sin timezone para ahorrar bytes: 19 chars. Total data = 14+19 = 33 bytes ≤ 38 max
	ts := time.Now().Format("2006-01-02T15:04:05")
	customData := []byte("Hello " + ts)
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

func sendCustomSYN(srcIPStr, dstIPStr string, dstPort uint16, data []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Opción 253 (experimental): type(1) + length(1) + data
	opts := []byte{253, byte(2 + len(data))}
	opts = append(opts, data...)

	srcIP := net.ParseIP(srcIPStr).To4()
	dstIP := net.ParseIP(dstIPStr).To4()
	packet := buildTCPSYN(srcIP, dstIP, 44444, dstPort, opts)

	addr := syscall.SockaddrInet4{Port: int(dstPort)}
	copy(addr.Addr[:], dstIP)
	return syscall.Sendto(fd, packet, 0, &addr)
}
