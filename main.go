//go:build linux
// +build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sample.bpf.c -target bpfel -type event -- -I/usr/include/ -O2 -g -D__TARGET_ARCH_x86 -fno-stack-protector

type eventBPF struct {
	Pid   uint32
	PidNS uint32
	MntNS uint32
	Comm  [80]uint8
	Daddr uint32
}

// nskey Structure acts as an Identifier for containers
type nskey struct {
	PidNS uint32
	MntNS uint32
}

type deets struct {
	ContainerID   string
	ContainerName string
	ContainerPID  string
	ProcessName   string
	ProcessPID    uint32
}
type pathKey struct {
	Pid    uint32
	Mnt_ns uint32
	Path   [256]byte
}

var cmap map[nskey]deets

func newPathKey(pid uint32, mnt_ns uint32, path string) pathKey {
	var key pathKey
	key.Pid = pid
	key.Mnt_ns = mnt_ns
	copy(key.Path[:], path)
	return key
}

func main() {

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	// populatemap()

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		panic(err)
	}

	cmap = make(map[nskey]deets)

	for _, container := range containers {
		inspect, _ := cli.ContainerInspect(context.Background(), container.ID)
		c := deets{}

		c.ContainerID = inspect.ID
		c.ContainerName = strings.TrimLeft(inspect.Name, "/")
		pid := strconv.Itoa(inspect.State.Pid)
		c.ContainerPID = pid

		key := nskey{}

		if data, err := os.Readlink("/proc/" + pid + "/ns/pid"); err == nil {
			fmt.Sscanf(data, "pid:[%d]\n", &key.PidNS)
		}

		if data, err := os.Readlink("/proc/" + pid + "/ns/mnt"); err == nil {
			fmt.Sscanf(data, "mnt:[%d]\n", &key.MntNS)
		}

		cmap[key] = c
	}

	// fn := "sys_execve"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpa, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceBprm})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	//execve execveat
	kpa1, err := link.Kprobe("sys_execve", objs.KprobeExecve, &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpa.Close()
	defer kpa1.Close()

	// create container map for nginx contianer and inner map

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")
	var event eventBPF
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		key := nskey{
			PidNS: event.PidNS,
			MntNS: event.MntNS,
		}

		if val, ok := cmap[key]; ok {
			val.ProcessPID = event.Pid
			val.ProcessName = unix.ByteSliceToString(event.Comm[:])
			ipBytes := make([]byte, 4)
			// Fill the byte slice with the IP address in big-endian format.
			binary.LittleEndian.PutUint32(ipBytes, event.Daddr)

		}

	}
}
