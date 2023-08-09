// ***********************************************************************
// Go Network Monitor - personal project
// Originally written by Greg Herlein (https://github.com/gherlein/gonetmon
// Released under the MIT License:  https://gherlein.mit-license.org/
// ***********************************************************************
// Modified by Steven Giacomelli (steve@giaacomelli.ca) to simplify containerization
// ***********************************************************************
// This program is a simple network monitor that will listen on a network
// interface and count the number of bytes seen on the network.  It will
// also count the number of bytes seen on each node of the network.
// ***********************************************************************

package main

import (
	"flag"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// metrics is a struct to hold all the prometheus metrics
type metrics struct {
	networkTraffic *prometheus.CounterVec // counter for total network traffic
}

// packetSummary is a struct to hold a summary of a packet
type packetSummary struct {
	interfaceName  string
	sourceMAC      string
	destinationMAC string
	sourceIP       string
	destinationIP  string
	protocol       string
	length         int
}

// packetDecoder is a struct to hold the packet decoder
type packetDecoder struct {
	ethernetLayer          layers.Ethernet
	ip4Layer               layers.IPv4
	ip6Layer               layers.IPv6
	tcpLayer               layers.TCP
	udpLayer               layers.UDP
	decodingLayerContainer gopacket.DecodingLayerContainer
	decoder                gopacket.DecodingLayerFunc
	decoded                []gopacket.LayerType
}

var (
	log                 = logrus.New() // logger
	logLevel            = "info"       // default log level
	prometheusPort      = 9338         // default port to export metrics
	monitoredInterfaces []string       // interfaces to monitor
)

func init() {
	interfaceNames := parseFlags()         // parse command line flags
	initLogger()                           // initialize the logger
	setMonitoredInterfaces(interfaceNames) // set the interfaces to monitor
}

func main() {
	reg := prometheus.NewRegistry()
	metrics := newMetrics(reg)

	go func() {
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(prometheusPort), nil))
	}()

	var wg sync.WaitGroup
	for _, i := range monitoredInterfaces {
		wg.Add(1)
		go func(interfaceName string) {
			defer wg.Done()
			if err := scanInterface(interfaceName, metrics); err != nil {
				log.Fatal(err)
			}
		}(i)
	}
	wg.Wait()
}

func setMonitoredInterfaces(interfaceNames string) {
	// get interfaces to monitor
	if defaultInterfaces, err := getDefaultInterfaces(); err != nil {
		log.Fatal(err)
	} else {
		for _, i := range strings.Split(interfaceNames, ",") {
			var trimmedInterfaceName = strings.TrimSpace(i)
			for _, j := range defaultInterfaces {
				if strings.EqualFold(trimmedInterfaceName, j) {
					monitoredInterfaces = append(monitoredInterfaces, trimmedInterfaceName)
				}
			}
		}
	}

	if len(monitoredInterfaces) == 0 {
		if len(interfaceNames) == 0 {
			log.Fatal("No interfaces specified to monitor")
		}
		log.Fatal("Cannot monitor any of the specified interfaces (", interfaceNames, ")")
	}
}

func parseFlags() string {
	var interfaceNames = ""
	// get the command line params
	flag.StringVar(&interfaceNames, "interfaces", "", "names of the network interfaces to monitor (comma separated)")
	flag.IntVar(&prometheusPort, "port", 9338, "port to export metrics")
	flag.StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error, fatal, panic)")
	flag.Parse()
	return interfaceNames
}

func initLogger() {
	if lvl, err := logrus.ParseLevel(logLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.SetLevel(logrus.InfoLevel)
		log.Trace("Invalid log level specified (", logLevel, "), defaulting to info")
	}
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		networkTraffic: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "network_bytes_total",
			Help: "Number of bytes seen on the network.",
		}, []string{"interfaceName", "srcMAC", "dstMAC", "srcIP", "dstIP", "protocol"}),
	}
	reg.MustRegister(m.networkTraffic)
	return m
}

func (m *metrics) updateMetrics(summary *packetSummary) {
	m.networkTraffic.WithLabelValues(summary.interfaceName, summary.sourceMAC, summary.destinationMAC, summary.sourceIP, summary.destinationIP, summary.protocol).Add(float64(summary.length))
}

func newPacketDecoder() *packetDecoder {
	var ethernetLayer layers.Ethernet
	var ip4Layer layers.IPv4
	var ip6Layer layers.IPv6
	var tcpLayer layers.TCP
	var udpLayer layers.UDP
	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc.Put(&ethernetLayer)
	dlc.Put(&ip4Layer)
	dlc.Put(&ip6Layer)
	dlc.Put(&tcpLayer)
	dlc.Put(&udpLayer)

	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

	return &packetDecoder{
		ethernetLayer:          ethernetLayer,
		ip4Layer:               ip4Layer,
		ip6Layer:               ip6Layer,
		tcpLayer:               tcpLayer,
		udpLayer:               udpLayer,
		decodingLayerContainer: dlc,
		decoder:                decoder,
		decoded:                decoded,
	}
}

func (p *packetDecoder) decode(handle *pcapgo.EthernetHandle, interfaceName string) (*packetSummary, error) {
	if packetData, _, err := handle.ZeroCopyReadPacketData(); err != nil {
		if err == io.EOF {
			return nil, err
		}
		log.Fatal(err)

	} else {
		var srcMAC, destMac net.HardwareAddr
		var srcIP, destIP net.IP
		var protocol = "unknown"
		var packetLength int

		if lt, err := p.decoder(packetData, &p.decoded); err != nil {
			log.Debug("Error decoding packet: %s", err)
			return nil, err
		} else if lt != gopacket.LayerTypeZero {
			log.Debug("Unknown layer type: %v", lt)
			return nil, err
		}

		packetLength = len(packetData)

		for _, layerType := range p.decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				srcMAC = p.ethernetLayer.SrcMAC
				destMac = p.ethernetLayer.DstMAC
			case layers.LayerTypeIPv4:
				srcIP = p.ip4Layer.SrcIP
				destIP = p.ip4Layer.DstIP
			case layers.LayerTypeIPv6:
				if srcIP == nil && destIP == nil {
					srcIP = p.ip6Layer.SrcIP
					destIP = p.ip6Layer.DstIP
				}
			case layers.LayerTypeTCP:
				protocol = "tcp"
			case layers.LayerTypeUDP:
				protocol = "udp"
			default:
				continue
			}
		}

		log.Trace("srcMAC: %v, destMac: %v, srcIP: %v, destIP: %v, protocol: %s, packetLength: %d", srcMAC, destMac, srcIP, destIP, protocol, packetLength)

		return &packetSummary{
			interfaceName:  interfaceName,
			sourceMAC:      srcMAC.String(),
			destinationMAC: destMac.String(),
			sourceIP:       srcIP.String(),
			destinationIP:  destIP.String(),
			protocol:       protocol,
			length:         packetLength,
		}, nil
	}
	return nil, nil
}

func scanInterface(interfaceName string, metrics *metrics) error {
	log.Infof("Scanning interface %s", interfaceName)
	if handle, err := pcapgo.NewEthernetHandle(interfaceName); err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()
		stop := make(chan struct{})
		go readPacket(handle, interfaceName, metrics, stop)
		defer close(stop)
	}
	return nil
}

func readPacket(handle *pcapgo.EthernetHandle, interfaceName string, metrics *metrics, stop chan struct{}) {
	decoder := newPacketDecoder()
	for {
		select {
		case <-stop:
			log.Infof("Stopping interface %s", interfaceName)
			return
		default:
			if summary, err := decoder.decode(handle, interfaceName); err != nil {
				continue
			} else if summary != nil {
				metrics.updateMetrics(summary)
			}
		}
	}
}

func getDefaultInterfaces() ([]string, error) {

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	var defaultInterfaces []string
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		if i.Flags&net.FlagPointToPoint != 0 {
			continue // point-to-point interface
		}
		addrs, err := i.Addrs()
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		if len(addrs) == 0 {
			continue // interface has no addresses
		}
		defaultInterfaces = append(defaultInterfaces, i.Name)
	}

	return defaultInterfaces, nil
}
