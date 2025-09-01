package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sample.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

func main() {
	// Load the compiled eBPF objects.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Get a list of all network interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("failed to get network interfaces: %v", err)
	}
	var links []link.Link

	for _, iface := range ifaces {
		// Skip loopback interfaces and interfaces that are down.
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.HandleIngress,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("could not attach ingress program to %s: %s", iface.Name, err)
			continue
		}
		links = append(links, l) // for cleanup later
		log.Printf("Attached INGRESS on iface %q (index %d)", iface.Name, iface.Index)

		// Attach the egress TC program.
		l2, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.HandleEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("could not attach egress %s , %v", iface.Name, err)
			continue
		}
		links = append(links, l2)

		log.Printf("Attached EGRESS on iface %s (index %d)", iface.Name, iface.Index)
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Monitoring traffic. Press Ctrl+C to exit.")

	var lastIngressBytes, lastEgressBytes uint64

	for {
		select {
		case <-ticker.C:
			var perCpuValues []uint64
			var ingressBytes, egressBytes uint64

			if err := objs.TrafficStats.Lookup(uint32(0), &perCpuValues); err != nil {
				log.Printf("Error reading ingress stats: %v", err)
				continue
			}
			for _, val := range perCpuValues {
				ingressBytes += val
			}

			if err := objs.TrafficStats.Lookup(uint32(1), &perCpuValues); err != nil {
				log.Printf("Error reading egress stats: %v", err)
				continue
			}
			for _, val := range perCpuValues {
				egressBytes += val
			}

			ingressRate := float64(ingressBytes-lastIngressBytes) / 1024.0
			egressRate := float64(egressBytes-lastEgressBytes) / 1024.0

			fmt.Printf("\rTotal Ingress: %.2f KB/s | Total Egress: %.2f KB/s ", ingressRate, egressRate)

			lastIngressBytes = ingressBytes
			lastEgressBytes = egressBytes

		case <-stop:
			fmt.Println("\nReceived signal, detaching programs and exiting.")
			return
		}
	}
}
