package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"time"
    "strings"
    "sync"

	"pcap-go/pkg/cmd-utils"
	"pcap-go/pkg/lib"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	fingerprintToMatch   = flag.String("white", "", "fingerprints to match")
	fingerprintToUnmatch = flag.String("black", "", "fingerprints to not match")
	regexStr             = flag.String("r", "", "regex to match")
	bpfStr               = flag.String("bpf", "", "BPF filter")
	hostString           = flag.String("host", "", "host IP to monitor (ignores outgoing traffic)")
	regex                *regexp.Regexp
)

var program *tea.Program

// PacketMsg is the message sent to the Bubble Tea UI
type PacketMsg struct {
	Haiku     string
	Delta     uint64
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Timestamp time.Time
	Payload   string
}

// TickMsg for UI updates
type TickMsg time.Time

func doTick() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func extractPayload(packet gopacket.Packet) string {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return ""
	}
	body := tcpLayer.LayerPayload()
    if len(body) == 0 {
        return ""
    }
	
	// Convert non-printable to dot
	res := make([]byte, len(body))
	nonPrintable := 0
	for i := 0; i < len(body); i++ {
		if body[i] < 32 || body[i] > 126 {
			nonPrintable++
			res[i] = '.'
		} else {
			res[i] = body[i]
		}
	}
    // Limit payload length for UI
    if len(res) > 500 {
        return string(res[:500]) + "..."
    }
	return string(res)
}

var (
	statsMutex   sync.RWMutex
	globalStats  = make(map[string]*HaikuStats)
	totalPkts    int
)

func capturePackets(ctx context.Context, source gopacket.PacketDataSource, handle *gopacket.PacketSource, fgsToMatch, fgsToUnmatch []string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := handle.NextPacket()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		networkFlow := networkLayer.NetworkFlow()
		
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		tcpFlow := transportLayer.TransportFlow()
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		// Ignora il traffico in cui la destinazione non è l'host, o l'host è il mittente (loopback)
		if *hostString != "" && (networkFlow.Dst().String() != *hostString || networkFlow.Src().String() == *hostString) {
			continue
		}

		fp, _, _, err := lib.ExtractFingerprint(packet)
		if err != nil {
			continue
		}

		if (*fingerprintToMatch != "" && !fp.ContainedIn(fgsToMatch)) || (*fingerprintToUnmatch != "" && fp.ContainedIn(fgsToUnmatch)) {
			continue
		}

		body := tcpLayer.LayerPayload()
		if regex != nil && !regex.Match(body) {
			continue
		}

		// Aggiornamento Thread-Safe delle statistiche
		statsMutex.Lock()
		totalPkts++
		haiku := fp.Haiku()
		stat, exists := globalStats[haiku]
		if !exists {
			stat = &HaikuStats{
				Haiku:     haiku,
				Delta:     fp.Delta,
				Count:     0,
				UniqueIPs: make(map[string]bool),
			}
			globalStats[haiku] = stat
		}

		stat.Count++
		stat.UniqueIPs[networkFlow.Src().String()] = true
		stat.LastSeen = packet.Metadata().Timestamp
		stat.LastSrc = fmt.Sprintf("%s:%s", networkFlow.Src(), tcpFlow.Src())
		stat.LastDst = fmt.Sprintf("%s:%s", networkFlow.Dst(), tcpFlow.Dst())
		
		payload := extractPayload(packet)
		if payload != "" {
			stat.LastPayload = payload
		}
		statsMutex.Unlock()
	}
}

func main() {
	var err error
	flag.Parse()

	fgsToMatch := strings.Split(*fingerprintToMatch, ",")
	fgsToUnmatch := strings.Split(*fingerprintToUnmatch, ",")

	if *regexStr != "" {
		regex, err = regexp.Compile(*regexStr)
		if err != nil {
			cmdUtils.LogFatalError("failed to compile regex:", err)
		}
	}

	if len(flag.Args()) != 1 {
		fmt.Println("Usage: euriclea-tui {input.pcap|-}")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	source, reader, err := lib.OpenPcapSource(flag.Arg(0))
	if err != nil {
		cmdUtils.LogFatalError("Failed to open pcap source", err)
	}
	if reader != os.Stdin {
		defer reader.Close()
	}

	err = source.SetBPFFilter(*bpfStr)
	if err != nil {
		cmdUtils.LogFatalError("failed to set BPF filter: ", err)
	}

	handle := gopacket.NewPacketSource(source, source.LinkType())

	// Initialize TUI
	m := initialModel()
	program = tea.NewProgram(m, tea.WithAltScreen())

	go capturePackets(ctx, source, handle, fgsToMatch, fgsToUnmatch)

	if _, err := program.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}
