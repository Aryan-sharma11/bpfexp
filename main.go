//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sample.bpf.c -target bpfel -type event -- -I/usr/include/ -O2 -g -D__TARGET_ARCH_x86 -fno-stack-protector

type BPFEnforcer struct {
	InnerMapSpec *ebpf.MapSpec
	// InnerMapSpec            *ebpf.MapSpec
	BPFPathMap *ebpf.Map
	BPFArgsMap *ebpf.Map
	obj        bpfObjects
}
type eventBPF struct {
	Pid   uint32
	PidNS uint32
	MntNS uint32
	Comm  [80]uint8
	Daddr uint32
}

// nskey Structure acts as an Identifier for containers

type mapKey struct {
	Pid   uint32
	Mntid uint32
	Path  [255]byte
	_     byte
}

func newPathKey(pid uint32, mnt_ns uint32, path string) mapKey {
	var key mapKey
	key.Pid = pid
	key.Mntid = mnt_ns
	copy(key.Path[:], path)
	// if len(path) < 255 {
	// 	key.Path[len(path)] = 0 // Manually add null termination
	// }
	return key
}

func main() {
	y := uint32(unsafe.Sizeof(mapKey{}))
	// populatemap()
	be := BPFEnforcer{}
	var err error
	be.BPFPathMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    y,
		ValueSize:  1,
		MaxEntries: 100,
		Name:       "path_map",
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf/",
	})
	if err != nil {
		fmt.Println("error loading path_map ", err)
	}

	be.BPFArgsMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    y,
		ValueSize:  1,
		MaxEntries: 100,
		Name:       "args_map",
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf/",
	})
	if err != nil {
		fmt.Println("error loading args_map ", err)
	}

	if err := loadBpfObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/",
		},
	}); err != nil {
		fmt.Println("error loading objects", err)
	}
	keyPath := newPathKey(uint32(4026532833), uint32(4026533709), "/usr/bin/apt")

	// keyArgs := newPathKey(uint32(4026532833), uint32(4026533709), "update")
	valPath := uint8(1)
	var valArgs uint8 = 1
	//pid = 4026532833  mntid = 4026533709

	allowedArgs := [3]string{"-u", "-m", "helloworld"}

	for _, arg := range allowedArgs {
		keyArgs := newPathKey(uint32(4026533709), uint32(4026532833), arg)
		err = be.BPFArgsMap.Put(keyArgs, valArgs)
		if err != nil {
			fmt.Println("args map error ", err)
		}
		fmt.Printf("Size of mapKey struct: %d bytes\n", unsafe.Sizeof(keyArgs))
		fmt.Printf("Key PID: %d, MNTID: %d, Path: %s\n", keyArgs.Pid, keyArgs.Mntid, keyArgs.Path[:])
	}

	err = be.BPFPathMap.Put(keyPath, valPath)
	if err != nil {
		fmt.Println("path map error ", err)
	}

	// fn := "sys_execve"
	kpa, err := link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceBprm})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	//execve execveat
	kpa1, err := link.Kprobe("sys_execve", be.obj.KprobeExecve, &link.KprobeOptions{})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpa.Close()
	defer kpa1.Close()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	rd, err := ringbuf.NewReader(be.obj.Events)
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

	}

	//delete maps
	// if be.BPFArgsMap != nil {
	// 	if err = be.BPFArgsMap.Close(); err != nil {
	// 		fmt.Println("error :", err)
	// 	}
	// }
}

// bash-41120   [003] ...11  4950.223822: bpf_trace_printk:  source = /usr/bin/bash  path = /usr/bin/apt
