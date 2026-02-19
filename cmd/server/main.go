package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	listenPort := os.Args[1]
	port, err := strconv.Atoi(listenPort)
	if err != nil {
		panic("Puerto inválido")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

	fmt.Printf("Escuchando paquetes TCP SYN en puerto %d...\n", port)

	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			panic(err)
		}

		// El raw socket con IPPROTO_TCP incluye la cabecera IP en los datos recibidos
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok || !tcp.SYN || tcp.DstPort != layers.TCPPort(port) {
			continue
		}

		fmt.Printf("Paquete SYN recibido de %s:%d\n", packet.NetworkLayer().NetworkFlow().Src().String(), tcp.SrcPort)

		for _, opt := range tcp.Options {
			if opt.OptionType == 253 {
				fmt.Printf("Datos recibidos: %s\n", string(opt.OptionData))
			}
		}
	}
}
