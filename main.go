package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const DefaultWindow = 50

type EventConfig struct {
	Plot bool
	UpSymbol string
	DownSymbol string
	Color string
	Label string
	LabelAll bool
	TextItem string
	PlotAllUp bool
	PlotAllDown bool
}

var Config = map[EventType]EventConfig {
	EventTypeECT: {
		Plot: false,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "white",
		Label: "ECT",
		LabelAll: false,
		TextItem: "ltext",
		PlotAllUp: false,
		PlotAllDown: false,
	},
	EventTypeSCE: {
		Plot: true,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "yellow",
		Label: "SCE",
		LabelAll: false,
		TextItem: "ltext",
		PlotAllUp: true,
		PlotAllDown: false,
	},
	EventTypeCE: {
		Plot: true,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "red",
		Label: "CE",
		LabelAll: true,
		TextItem: "ltext",
		PlotAllUp: false,
		PlotAllDown: false,
	},
	EventTypeECE: {
		Plot: true,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "blue",
		Label: "ECE",
		LabelAll: false,
		TextItem: "ltext",
		PlotAllUp: false,
		PlotAllDown: false,
	},
	EventTypeCWR: {
		Plot: true,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "green",
		Label: "CWR",
		LabelAll: false,
		TextItem: "ltext",
		PlotAllUp: false,
		PlotAllDown: false,
	},
	EventTypeNS: {
		Plot: true,
		UpSymbol: "rarrow",
		DownSymbol: "larrow",
		Color: "purple",
		Label: "NS",
		LabelAll: false,
		TextItem: "ltext",
		PlotAllUp: false,
		PlotAllDown: false,
	},
}

type EventType int

const (
	EventTypeECT EventType = 1 << iota
	EventTypeSCE
	EventTypeCE
	EventTypeECE
	EventTypeCWR
	EventTypeNS
)

const EventTypeCount = 6

type ECN uint8

const (
	NotECT ECN = 0x00
	SCE    ECN = 0x01
	ECT    ECN = 0x02
	CE     ECN = 0x03
)

type Packet struct {
	Timestamp   time.Time
	Length      int
	EventType   EventType
	Proportions map[EventType]uint
	PropWinSize uint
}

func NewPacket(ts time.Time, length int) *Packet {
	return &Packet{ts, length, EventType(0), make(map[EventType]uint), 0}
}

func (p *Packet) AddEvent(et EventType) {
	p.EventType |= et
}

func (p *Packet) TimevalString() string {
	tv := syscall.NsecToTimeval(p.Timestamp.UnixNano())
	return fmt.Sprintf("%d.%.6d", tv.Sec, tv.Usec)
}

type FlowData struct {
	TransportFlow gopacket.Flow
	NetworkFlow   gopacket.Flow
	UpPackets     []Packet
	DownPackets   []Packet
	UpCounts      map[EventType]uint
	DownCounts    map[EventType]uint
}

func NewFlowData(tf gopacket.Flow) *FlowData {
	return &FlowData{tf, gopacket.Flow{}, make([]Packet, 0), make([]Packet, 0),
		make(map[EventType]uint), make(map[EventType]uint)}
}

func (fd *FlowData) CountEvent(et EventType, up bool) {
	if up {
		fd.UpCounts[et]++
	} else {
		fd.DownCounts[et]++
	}
}

func (fd *FlowData) addIPEvent(p *Packet, up bool, networkFlow gopacket.Flow, newFlow bool, dscp uint8) {
	if newFlow {
		fd.NetworkFlow = networkFlow
	}

	switch ECN(dscp & 0x03) {
	case NotECT:
		//p.AddEvent(EventTypeNotECT)
		//fd.CountEvent(EventTypeNotECT, up)
	case SCE:
		p.AddEvent(EventTypeSCE)
		fd.CountEvent(EventTypeSCE, up)
	case ECT:
		p.AddEvent(EventTypeECT)
		fd.CountEvent(EventTypeECT, up)
	case CE:
		p.AddEvent(EventTypeCE)
		fd.CountEvent(EventTypeCE, up)
	}
}

func (fd *FlowData) AddPacket(gp gopacket.Packet, tcp *layers.TCP, up bool, newFlow bool) {
	m := gp.Metadata()
	p := NewPacket(m.CaptureInfo.Timestamp, m.Length)
	if !tcp.SYN {
		if tcp.CWR {
			p.AddEvent(EventTypeCWR)
			fd.CountEvent(EventTypeCWR, up)
		}
		if tcp.ECE {
			p.AddEvent(EventTypeECE)
			fd.CountEvent(EventTypeECE, up)
		}
		if tcp.NS {
			p.AddEvent(EventTypeNS)
			fd.CountEvent(EventTypeNS, up)
		}
	
		if ip4l := gp.Layer(layers.LayerTypeIPv4); ip4l != nil {
			ip4, _ := ip4l.(*layers.IPv4)
			fd.addIPEvent(p, up, ip4.NetworkFlow(), newFlow, ip4.TOS)
		}
	
		if ip6l := gp.Layer(layers.LayerTypeIPv6); ip6l != nil {
			ip6, _ := ip6l.(*layers.IPv6)
			fd.addIPEvent(p, up, ip6.NetworkFlow(), newFlow, ip6.TrafficClass)
		}
	}

	if up {
		fd.UpPackets = append(fd.UpPackets, *p)
	} else {
		fd.DownPackets = append(fd.DownPackets, *p)
	}
}

func (fd *FlowData) FlowString() string {
	//return fmt.Sprintf("%s:%s-%s:%s", fd.NetworkFlow.Src(), fd.TransportFlow.Src(),
	//	fd.NetworkFlow.Dst(), fd.TransportFlow.Dst())
	//return fmt.Sprintf("%s:%s-%s:%s", "10.9.254.10", fd.TransportFlow.Src(),
	//	"10.9.0.10", fd.TransportFlow.Dst())
	return fmt.Sprintf("%s-%s", fd.TransportFlow.Src(), fd.TransportFlow.Dst())
}

func parse(h *pcap.Handle) map[gopacket.Flow]*FlowData {
	data := make(map[gopacket.Flow]*FlowData)
	psrc := gopacket.NewPacketSource(h, h.LinkType())
	for p := range psrc.Packets() {
		if tlyr := p.Layer(layers.LayerTypeTCP); tlyr != nil {
			tcp, _ := tlyr.(*layers.TCP)
			tf := tcp.TransportFlow()
			newFlow := false
			up := true
			var fd *FlowData
			var okf bool
			if fd, okf = data[tf]; !okf {
				var okr bool
				if fd, okr = data[tf.Reverse()]; !okr {
					fd = NewFlowData(tf)
					data[tf] = fd
					newFlow = true
				} else {
					up = false
				}
			}
			fd.AddPacket(p, tcp, up, newFlow)
		}
	}

	return data
}

func processPackets(packets []Packet, window int) {
	for i := 0; i < len(packets); i++ {
		p := &packets[i]
		j1 := i - window
		j2 := i + window
		if j1 < 0 {
			j1 = 0
		}
		if j2 > len(packets) {
			j2 = len(packets)
		}

		for j := j1; j < j2; j++ {
			for et := EventType(1); et < EventType(1<<EventTypeCount); et <<= 1 {
				if packets[j].EventType&et != EventType(0) {
					p.Proportions[et]++
				}
			}
			p.PropWinSize++
		}
	}
}

func process(data map[gopacket.Flow]*FlowData, window int) {
	for _, v := range data {
		fmt.Printf("%s:\n", v.FlowString())
		fmt.Printf("   Up:   SCE=%d, CE=%d, ECE=%d, CWR=%d, NS=%d, total=%d\n",
			v.UpCounts[EventTypeSCE], v.UpCounts[EventTypeCE],
			v.UpCounts[EventTypeECE], v.UpCounts[EventTypeCWR],
			v.UpCounts[EventTypeNS], len(v.UpPackets))
		fmt.Printf("   Down: SCE=%d, CE=%d, ECE=%d, CWR=%d, NS=%d, total=%d\n",
			v.DownCounts[EventTypeSCE], v.DownCounts[EventTypeCE],
			v.DownCounts[EventTypeECE], v.DownCounts[EventTypeCWR],
			v.DownCounts[EventTypeNS], len(v.DownPackets))

		processPackets(v.UpPackets, window)
		processPackets(v.DownPackets, window)
	}
}

func xplotPackets(w io.Writer, up bool, packets []Packet, lines bool) {
	etmask := EventType(0)
	for i, p := range packets {
		for et := EventType(1); et < EventType(1<<EventTypeCount); et <<= 1 {
			if p.EventType&et != EventType(0) ||
				(up && Config[et].PlotAllUp) || (!up && Config[et].PlotAllDown) {
				tv := p.TimevalString()
				prop := float64(p.Proportions[et]) / float64(p.PropWinSize)
				var symbol string
				if up {
					symbol = Config[et].UpSymbol
				} else {
					symbol = Config[et].DownSymbol
				}

				if Config[et].Plot {
					fmt.Fprintf(w, "%s %s %f %s\n", symbol, tv, prop, Config[et].Color)
					if Config[et].LabelAll || etmask&et == 0 {
						fmt.Fprintf(w, "%s %s %f %s\n", Config[et].TextItem, tv, prop,
							Config[et].Color)
						fmt.Fprintln(w, Config[et].Label)
						etmask |= et
					}

					if lines {
						for j := i - 1; j >= 0; j-- {
							jp := packets[j]
							if jp.EventType&et != EventType(0) {
								fmt.Fprintf(w, "line %s %f %s %f %s\n",
									jp.TimevalString(),
									float64(jp.Proportions[et])/float64(jp.PropWinSize),
									p.TimevalString(),
									float64(p.Proportions[et])/float64(p.PropWinSize),
									Config[et].Color)
								break
							}
						}
					}
				}
			}
		}
	}
}

func xplot(data map[gopacket.Flow]*FlowData, lines bool) error {
	for _, v := range data {
		f, err := os.Create(v.FlowString() + ".xpl")
		if err != nil {
			return err
		}
		defer func(f *os.File) {
			f.Close()
		}(f)

		w := bufio.NewWriter(f)
		fmt.Fprintln(w, "timeval double")
		fmt.Fprintln(w, "title")
		fmt.Fprintln(w, v.FlowString())
		fmt.Fprintln(w, "xlabel")
		fmt.Fprintln(w, "Time")
		fmt.Fprintln(w, "ylabel")
		fmt.Fprintln(w, "Proportion")
		xplotPackets(w, true, v.UpPackets, lines)
		xplotPackets(w, false, v.DownPackets, lines)
		fmt.Fprintln(w, "go")
		w.Flush()
	}

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [-l] pcapfile\n", os.Args[0])
		flag.PrintDefaults()
	}

	lines := flag.Bool("l", false, "plot lines between points")
	window := flag.Int("w", DefaultWindow, "proportion window size")
	flag.Parse()

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	h, err := pcap.OpenOffline(flag.Args()[0])
	if err != nil {
		fmt.Printf("Unable to open pcap file %s (%s)\n", flag.Args()[0], err)
		os.Exit(1)
	}
	defer func(h *pcap.Handle) {
		h.Close()
	}(h)

	data := parse(h)

	process(data, *window)

	if err = xplot(data, *lines); err != nil {
		fmt.Println("Error writing plots:", err)
		os.Exit(1)
	}
}
