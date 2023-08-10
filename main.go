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
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	flag "github.com/spf13/pflag"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	log                 = logrus.New() // logger
	interfaceNames      []string       // interfaces to monitor
	logLevel            = "info"       // default log level
	prometheusPort      = 9338         // default port to export metrics
	monitoredInterfaces []string       // interfaces to monitor
)

//***********************************************************************
// Metrics
//***********************************************************************

// metrics is a struct to hold all the prometheus metrics
type metrics struct {
	networkTraffic *prometheus.CounterVec // counter for total network traffic
	dnsRequests    *prometheus.CounterVec // counter for DNS requests
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		networkTraffic: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "network_bytes_total",
			Help: "Number of bytes seen on the network.",
		}, []string{"interfaceName", "srcMAC", "dstMAC", "srcIP", "dstIP"}),

		dnsRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_requests_total",
			Help: "Number of DNS requests seen on the network."},
			[]string{"interfaceName", "srcIP", "dnsName"}),
	}

	reg.MustRegister(m.networkTraffic)
	reg.MustRegister(m.dnsRequests)

	return m
}

type networkMetric interface {
	updateMetric(metrics *metrics) error
}

//***********************************************************************
// Packet Decoder
//***********************************************************************

// packetSummary is a struct to hold a summary of a packet
type packetSummary struct {
	interfaceName  string
	sourceMAC      string
	destinationMAC string
	sourceIP       string
	destinationIP  string
	length         int
}

func (p *packetSummary) updateMetric(metrics *metrics) error {
	metrics.networkTraffic.WithLabelValues(
		p.interfaceName,
		p.sourceMAC,
		p.destinationMAC,
		p.sourceIP,
		p.destinationIP).Add(float64(p.length))
	return nil
}

func (p *packetSummary) String() string {
	return strings.Join([]string{
		p.interfaceName,
		p.sourceMAC,
		p.destinationMAC,
		p.sourceIP,
		p.destinationIP,
		strconv.Itoa(p.length),
	}, ",")
}

func newPacketSummary(interfaceName string,
	sourceMAC,
	destinationMAC net.HardwareAddr,
	sourceIPv4,
	destinationIPv4,
	sourceIPv6,
	destinationIPv6 net.IP,
	length int) *packetSummary {

	if sourceIPv4 != nil || destinationIPv4 != nil {
		return &packetSummary{
			interfaceName:  interfaceName,
			sourceMAC:      sourceMAC.String(),
			destinationMAC: destinationMAC.String(),
			sourceIP:       sourceIPv4.String(),
			destinationIP:  destinationIPv4.String(),
			length:         length,
		}
	}
	return &packetSummary{
		interfaceName:  interfaceName,
		sourceMAC:      sourceMAC.String(),
		destinationMAC: destinationMAC.String(),
		sourceIP:       sourceIPv6.String(),
		destinationIP:  destinationIPv6.String(),
		length:         length,
	}
}

type dnsRequest struct {
	interfaceName string
	sourceIP      string
	dnsName       string
}

func newDNSRequests(interfaceName string, sourceIPv4, sourceIpv6 net.IP, dnsLayer *layers.DNS) []networkMetric {
	if dnsLayer == nil || dnsLayer.QR {
		return nil
	}

	var srcIP string

	if sourceIPv4 != nil {
		srcIP = sourceIPv4.String()
	} else if sourceIpv6 != nil {
		srcIP = sourceIpv6.String()
	} else {
		srcIP = "unknown"
	}

	dnsRequests := make([]networkMetric, 0, len(dnsLayer.Questions))
	for _, question := range dnsLayer.Questions {
		dnsRequests = append(dnsRequests, &dnsRequest{
			interfaceName: interfaceName,
			sourceIP:      srcIP,
			dnsName:       string(question.Name),
		})
	}

	return dnsRequests
}

func (d *dnsRequest) updateMetric(metrics *metrics) error {
	metrics.dnsRequests.WithLabelValues(
		d.interfaceName,
		d.sourceIP,
		d.dnsName).Inc()
	return nil
}

// packetDecoder is a struct to hold the packet decoder
type packetDecoder struct {
	interfaceName string
	layers        []interface{}
	dlc           gopacket.DecodingLayerContainer
	decoder       gopacket.DecodingLayerFunc
	decoded       []gopacket.LayerType
}

func newPacketDecoder(interfaceName string) *packetDecoder {
	log.Trace("Creating new packet decoder")

	var ethernetLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var ipv6Layer layers.IPv6
	var dnsLayer layers.DNS
	var payloadLayer gopacket.Payload

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerMap{})
	dlc = dlc.Put(&ethernetLayer)
	dlc = dlc.Put(&ipv4Layer)
	dlc = dlc.Put(&ipv6Layer)
	dlc = dlc.Put(&dnsLayer)
	dlc = dlc.Put(&payloadLayer)

	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

	return &packetDecoder{
		interfaceName: interfaceName,
		layers: []interface{}{
			&ethernetLayer,
			&ipv4Layer,
			&ipv6Layer,
			&dnsLayer,
			&payloadLayer,
		},
		dlc:     dlc,
		decoder: decoder,
		decoded: decoded,
	}
}

func (p *packetDecoder) ethernetLayer() *layers.Ethernet {
	if m, ok := p.dlc.(gopacket.DecodingLayerMap); !ok {
		log.Trace("Ethernet layer found")
		return m[layers.LayerTypeEthernet].(*layers.Ethernet)
	}
	log.Trace("Ethernet layer not found")
	return nil
}

func (p *packetDecoder) ipv4Layer() *layers.IPv4 {
	if m, ok := p.dlc.(gopacket.DecodingLayerMap); !ok {
		return m[layers.LayerTypeIPv4].(*layers.IPv4)
	}
	return nil
}

func (p *packetDecoder) ipv6Layer() *layers.IPv6 {
	if m, ok := p.dlc.(gopacket.DecodingLayerMap); !ok {
		return m[layers.LayerTypeIPv6].(*layers.IPv6)
	}
	return nil
}

func (p *packetDecoder) dnsLayer() *layers.DNS {
	if m, ok := p.dlc.(gopacket.DecodingLayerMap); !ok {
		return m[layers.LayerTypeDNS].(*layers.DNS)
	}
	return nil
}

func (p *packetDecoder) payloadLayer() *gopacket.Payload {
	if m, ok := p.dlc.(gopacket.DecodingLayerMap); !ok {
		return m[gopacket.LayerTypePayload].(*gopacket.Payload)
	}
	return nil
}

func (p *packetDecoder) decodeMetrics(handle *pcapgo.EthernetHandle) ([]networkMetric, error) {
	if packetData, _, err := handle.ReadPacketData(); err != nil {
		if err == io.EOF {
			return nil, err
		}
		log.Fatal(err)
	} else {
		var srcMAC, destMac net.HardwareAddr
		var srcIPv4, destIPv4 net.IP
		var srcIPv6, destIPv6 net.IP
		var packetLength int

		var metrics []networkMetric

		if lt, err := p.decoder(packetData, &p.decoded); err != nil {
			log.Debug("Error decoding packet: ", err)
			return nil, err
		} else if lt != gopacket.LayerTypeZero {
			log.Warn("Unsupported layer type: ", lt)
		}

		packetLength = len(packetData)

		for _, layerType := range p.decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				srcMAC = p.ethernetLayer().SrcMAC
				destMac = p.ethernetLayer().DstMAC
			case layers.LayerTypeIPv4:
				srcIPv4 = p.ipv4Layer().SrcIP
				destIPv4 = p.ipv4Layer().DstIP
			case layers.LayerTypeIPv6:
				srcIPv6 = p.ipv6Layer().SrcIP
				destIPv6 = p.ipv6Layer().DstIP
			case layers.LayerTypeDNS:
				dnsRequests := newDNSRequests(p.interfaceName, srcIPv4, srcIPv6, p.dnsLayer())
				if dnsRequests != nil {
					metrics = append(metrics, dnsRequests...)
				}
			default:
				continue
			}

			summary := newPacketSummary(
				p.interfaceName,
				srcMAC,
				destMac,
				srcIPv4,
				destIPv4,
				srcIPv6,
				destIPv6,
				packetLength)

			log.Trace("Packet: ", summary)
			metrics = append(metrics, summary)

			return metrics, nil
		}
	}
	return nil, nil
}

//***********************************************************************
// Main
//***********************************************************************

func init() {
	parseFlags()             // parse command line flags
	initLogger()             // initialize the logger
	setMonitoredInterfaces() // set the interfaces to monitor
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

//***********************************************************************
// Utility Functions
//***********************************************************************

func setMonitoredInterfaces() {
	log.Trace("Setting monitored interfaces")
	// get interfaces to monitor
	if defaultInterfaces, err := getDefaultInterfaces(); err != nil {
		log.Fatal(err)
	} else {
		for _, i := range interfaceNames {
			for _, j := range defaultInterfaces {
				if strings.EqualFold(i, j) {
					monitoredInterfaces = append(monitoredInterfaces, i)
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

func parseFlags() {
	log.Trace("Parsing flags")
	// get the command line params
	flag.StringArrayVarP(&interfaceNames,
		"interfaces",
		"i",
		nil,
		"names of the network interfaces to monitor")
	flag.IntVarP(&prometheusPort,
		"port",
		"p",
		9338,
		"port to export metrics")
	flag.StringVarP(&logLevel,
		"log-level", "l",
		"info",
		"log level (debug, info, warn, error, fatal, panic)")
	flag.Parse()
}

func initLogger() {
	if lvl, err := logrus.ParseLevel(logLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.SetLevel(logrus.InfoLevel)
		log.Trace("Invalid log level specified (", logLevel, "), defaulting to info")
	}
}

func scanInterface(interfaceName string, metrics *metrics) error {
	log.Info("Starting interface ", interfaceName, " packet capture")
	if handle, err := pcapgo.NewEthernetHandle(interfaceName); err != nil {
		log.Fatal(err)
	} else {
		defer handle.Close()
		readPackets(handle, interfaceName, metrics)
	}
	return nil
}

func readPackets(handle *pcapgo.EthernetHandle,
	interfaceName string, metrics *metrics) {
	decoder := newPacketDecoder(interfaceName)
	for {
		if networkMetrics, err := decoder.decodeMetrics(handle); err != nil {
			continue
		} else if networkMetrics != nil {
			for _, m := range networkMetrics {
				err := m.updateMetric(metrics)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

func getDefaultInterfaces() ([]string, error) {
	log.Trace("Getting default interfaces")

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	var defaultInterfaces []string
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			log.Debug("Interface ", i.Name, " is down, ignoring")
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			log.Debug("Interface ", i.Name, " is loopback, ignoring")
			continue // loopback interface
		}
		if i.Flags&net.FlagPointToPoint != 0 {
			log.Debug("Interface ", i.Name, " is point-to-point, ignoring")
			continue // point-to-point interface
		}
		addrs, err := i.Addrs()
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		if len(addrs) == 0 {
			log.Debug("Interface ", i.Name, " has no addresses, ignoring")
			continue // interface has no addresses
		}
		log.Debug("Interface ", i.Name, " is a valid interface")
		defaultInterfaces = append(defaultInterfaces, i.Name)
	}

	return defaultInterfaces, nil
}
