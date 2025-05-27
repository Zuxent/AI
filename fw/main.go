package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dropbox/goebpf"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var elf = flag.String("elf", "bpf/ingress/xdp_ingress.o", "Compiled eBPF ELF file")
var filterAPI = flag.String("api", "", "API URL to fetch UDP patterns from")

// UdpPattern matches the structure in your eBPF code
type UdpPattern struct {
	Length      uint16
	ByteOffsets [8]uint8
	ByteValues  [8]uint8
	NumBytes    uint8
	Description [32]byte // Fixed-size array for description
}

type APIPattern struct {
	Length      uint16  `json:"length"`
	Offsets     []uint8 `json:"offsets"`
	Values      []uint8 `json:"values"`
	Description string  `json:"description"`
}

var (
	totalPktStatsMap goebpf.Map
	protocols        goebpf.Map
)

func main() {
	flag.Parse()
	if *iface == "" {
		fatalError("Error: -iface is required.")
	}

	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("Failed to load ELF: %v", err)
	}

	progArrayMap := bpf.GetMapByName("prog_array_map")
	if progArrayMap == nil {
		fatalError("Error: eBPF map 'prog_array_map' not found.")
	}

	packetCount := bpf.GetProgramByName("handler")
	if packetCount == nil {
		fatalError("Error: 'handler' program not found.")
	}
	err = packetCount.Load()
	if err != nil {
		fatalError("Failed to load 'handler': %v", err)
	}
	err = packetCount.Attach(*iface)
	if err != nil {
		fatalError("Failed to attach 'handler': %v", err)
	}
	fmt.Println("Successfully loaded and attached 'handler' as main function.")

	udpHandler := bpf.GetProgramByName("syn_challenge")
	if udpHandler == nil {
		fatalError("Error: 'syn_challenge' program not found.")
	}
	err = udpHandler.Load()
	if err != nil {
		fatalError("Failed to load 'syn_challenge': %v", err)
	}
	err = progArrayMap.Update(uint32(1), uint32(udpHandler.GetFd()))
	if err != nil {
		fatalError("Failed to update prog_array_map for 'syn_challenge': %v", err)
	}
	fmt.Println("Successfully loaded 'syn_challenge' and added to prog_array_map at index 1.")

	totalPktStatsMap = getMap(bpf, "totalPktStats")
	protocols = getMap(bpf, "protocols")
	patternMap := getMap(bpf, "pattern_map")

	var patterns []UdpPattern
	if *filterAPI != "" {
		patterns = fetchPatternsFromAPI(*filterAPI)
	} else {
		patterns = getHardcodedPatterns()
	}
	populatePatternMap(patternMap, patterns)

	defer func() {
		packetCount.Detach()
		fmt.Println("Detached 'handler'.")
		udpHandler.Detach()
		fmt.Println("Detached 'syn_challenge'.")
	}()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	ticker := time.NewTicker(3 * time.Second)
	fmt.Println("XDP program successfully loaded and attached. PPS refreshed every second.")
	time.Sleep(2 * time.Second)
	defer ticker.Stop()

	var prevPassedPackets, prevDroppedPackets uint64

	for {
		select {
		case <-ticker.C:
			printStats(&prevPassedPackets, &prevDroppedPackets)
		case <-ctrlC:
			fmt.Println("\033c\033[3J\nDetaching programs and exiting...")
			return
		}
	}
}

func getMap(bpf goebpf.System, name string) goebpf.Map {
	m := bpf.GetMapByName(name)
	if m == nil {
		fatalError("eBPF map '%s' not found", name)
	}
	return m
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func getHardcodedPatterns() []UdpPattern {
	return []UdpPattern{
		{
			Length:      14,
			ByteOffsets: [8]uint8{2, 3, 9, 10, 11, 12, 13},
			ByteValues:  [8]uint8{0x49, 0x01, 0x04, 0x63, 0x9e, 0x56, 0xca},
			NumBytes:    7,
			Description: func() (desc [32]byte) {
				copy(desc[:], "FiveM 14")
				return
			}(),
		},
	}
}

func fetchPatternsFromAPI(apiURL string) []UdpPattern {
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("Failed to fetch patterns from API: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("API responded with status: %s\n", resp.Status)
		return nil
	}

	var apiPatterns []APIPattern
	if err := json.NewDecoder(resp.Body).Decode(&apiPatterns); err != nil {
		fmt.Printf("Failed to decode API response: %v\n", err)
		return nil
	}

	var patterns []UdpPattern
	for _, p := range apiPatterns {
		var udpPat UdpPattern
		udpPat.Length = p.Length
		udpPat.NumBytes = uint8(len(p.Offsets))
		copy(udpPat.ByteOffsets[:], p.Offsets)
		copy(udpPat.ByteValues[:], p.Values)
		copy(udpPat.Description[:], p.Description)
		patterns = append(patterns, udpPat)
	}
	return patterns
}

func populatePatternMap(patternMap goebpf.Map, patterns []UdpPattern) {
	for i, pattern := range patterns {
		data := new(bytes.Buffer)
		err := binary.Write(data, binary.LittleEndian, pattern)
		if err != nil {
			fmt.Printf("Failed to serialize pattern %d: %v\n", i, err)
			continue
		}
		err = patternMap.Update(uint32(i), data.Bytes())
		if err != nil {
			fmt.Printf("Failed to update pattern map for key %d: %v\n", i, err)
		} else {
			fmt.Printf("Successfully updated pattern map for key %d\n", i)
		}
	}
}

func printStats(prevPassedPackets, prevDroppedPackets *uint64) {
	packetsPassed := getPacketsPassed()
	passedPPS := packetsPassed - *prevPassedPackets
	*prevPassedPackets = packetsPassed

	packetsDropped := getPacketsDropped()
	droppedPPS := packetsDropped - *prevDroppedPackets
	*prevDroppedPackets = packetsDropped

	var sb strings.Builder
	sb.WriteString("\033c\033[3J\u256D" + strings.Repeat("\u2500", 70) + "\u256E\n")
	sb.WriteString(fmt.Sprintf("Packets Passed (PPS): %d\n", passedPPS))
	sb.WriteString(fmt.Sprintf("Packets Dropped (PPS): %d\n", droppedPPS))
	sb.WriteString("Protocol Stats: " + getProtocolStats() + "\n")
	sb.WriteString("\u001b[35mZuxent Beta Firewall\u001b[0m\n")
	fmt.Print(sb.String())
}

func getPacketsPassed() uint64 {
	packetValue, err := totalPktStatsMap.Lookup(uint32(1))
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(packetValue)
}

func getPacketsDropped() uint64 {
	packetValue, err := totalPktStatsMap.Lookup(uint32(2))
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(packetValue)
}

func getProtocolStats() string {
	var sb strings.Builder
	for i := 0; i < 132; i++ {
		value, err := protocols.LookupInt(i)
		if err == nil && value > 0 {
			sb.WriteString(fmt.Sprintf("%s: %d ", getProtoName(i), value))
		}
	}
	return sb.String()
}

func getProtoName(proto int) string {
	switch proto {
	case syscall.IPPROTO_ENCAP:
		return "IPPROTO_ENCAP"
	case syscall.IPPROTO_GRE:
		return "IPPROTO_GRE"
	case syscall.IPPROTO_ICMP:
		return "IPPROTO_ICMP"
	case syscall.IPPROTO_IGMP:
		return "IPPROTO_IGMP"
	case syscall.IPPROTO_IPIP:
		return "IPPROTO_IPIP"
	case syscall.IPPROTO_SCTP:
		return "IPPROTO_SCTP"
	case syscall.IPPROTO_TCP:
		return "IPPROTO_TCP"
	case syscall.IPPROTO_UDP:
		return "IPPROTO_UDP"
	case 128:
		return "IPPROTO_ETHERIP"
	default:
		return fmt.Sprintf("Proto %d", proto)
	}
}
