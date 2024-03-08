// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package uprobetracer handles how uprobe/uretprobe/USDT programs are attached
// to containers. It has two running modes: `pending` mode and `running` mode.
//
// Before `AttachProg` is called, uprobetracer runs in `pending` mode, only
// maintaining the container PIDs ready to attach to.
//
// When `AttachProg` is called, uprobetracer enters the `running` mode and
// attaches to all pending containers. After that, it will never get back to
// the `pending` mode.
//
// In `running` mode, uprobetracer holds fd(s) of the executables, so we can
// use `/proc/self/fd/$fd` for attaching, it is used to avoid fd-reusing.
//
// Uprobetracer doesn't maintain ebpf.collection or perf-ring buffer by itself,
// those are hold by the parent tracer.
//
// All interfaces should hold locks, while inner functions do not.
//
// TODO: The current implementation doesn't consider any filtering
package uprobetracer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type ProgType int32

const (
	ProgUprobe    ProgType = 0
	ProgUretprobe ProgType = 1
)

type inodeUUID struct {
	fsId  unix.Fsid
	inode uint64
}

// inodeKeeper holds a file object, with the counter representing its
// reference count. The link is not nil only when the file is attached.
type inodeKeeper struct {
	counter int
	file    *os.File
	link    link.Link
}

func (t *inodeKeeper) close() {
	if t.link != nil {
		t.link.Close()
	}
	t.file.Close()
}

type Tracer[Event any] struct {
	progName       string
	progType       ProgType
	attachFilePath string
	attachSymbol   string
	prog           *ebpf.Program

	// keeps the inodeUUIDs for each attached container
	// when users write library names in ebpf section names, it's possible to
	// find multiple libraries of different archs within the same container,
	// making this a one-to-many mapping
	containerPid2Inode map[uint32][]inodeUUID
	// keeps the fd and refCount for each inodeUUID
	inodeRefCount map[inodeUUID]*inodeKeeper
	// used as a set, keeps PIDs of the pending containers
	pendingContainerPids map[uint32]bool

	closed bool

	mu sync.Mutex
}

func NewTracer[Event any]() (_ *Tracer[Event], err error) {
	t := &Tracer[Event]{
		containerPid2Inode:   make(map[uint32][]inodeUUID),
		inodeRefCount:        make(map[inodeUUID]*inodeKeeper),
		pendingContainerPids: make(map[uint32]bool),
		closed:               false,
	}
	return t, nil
}

// AttachProg loads ebpf program, and try attaching if there are pending containers
func (t *Tracer[Event]) AttachProg(progName string, progType ProgType, attachTo string, prog *ebpf.Program) error {
	if progType != ProgUprobe && progType != ProgUretprobe {
		return fmt.Errorf("unsupported uprobe prog type: %q", progType)
	}

	if prog == nil {
		return fmt.Errorf("prog does not exist")
	}
	if t.prog != nil {
		return fmt.Errorf("loading uprobe program twice")
	}

	parts := strings.Split(attachTo, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid section name %q", attachTo)
	}
	if !filepath.IsAbs(parts[0]) && strings.Contains(parts[0], "/") {
		return fmt.Errorf("section name must be either an absolute path or a library name: %q", parts[0])
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.progName = progName
	t.progType = progType
	t.attachFilePath = parts[0]
	t.attachSymbol = parts[1]
	t.prog = prog

	// attach to pending containers, then release the pending list
	for pid := range t.pendingContainerPids {
		t.attach(pid)
	}
	t.pendingContainerPids = nil

	return nil
}

func searchForLibrary(containerPid uint32, filePath string) []string {
	var libraryPaths []string
	var securedLibraryPaths []string

	if !filepath.IsAbs(filePath) {
		containerLdCachePath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), "etc/ld.so.cache")
		if err == nil {
			paths := parseLdCache(containerLdCachePath, filePath)
			libraryPaths = paths
		}
	} else {
		libraryPaths = append(libraryPaths, filePath)
	}
	for _, libraryPath := range libraryPaths {
		securedLibraryPath, err := securejoin.SecureJoin(filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root"), libraryPath)
		if err == nil {
			securedLibraryPaths = append(securedLibraryPaths, securedLibraryPath)
		}
	}
	return securedLibraryPaths
}

// attach ebpf program to a self-hosted inode
func (t *Tracer[Event]) attachEbpf(file *os.File) (link.Link, error) {
	attachPath := path.Join(host.HostProcFs, "self/fd/", fmt.Sprint(file.Fd()))
	ex, err := link.OpenExecutable(attachPath)
	if err != nil {
		return nil, fmt.Errorf("opening self-hosted file describer: %q, %q", attachPath, err.Error())
	}
	switch t.progType {
	case ProgUprobe:
		return ex.Uprobe(t.attachSymbol, t.prog, nil)
	case ProgUretprobe:
		return ex.Uretprobe(t.attachSymbol, t.prog, nil)
	default:
		return nil, fmt.Errorf("attaching to inode: unsupported prog type: %q", t.progType)
	}
}

// try attaching to a container, will update `containerPid2Inode` and `inodeRefCount`
func (t *Tracer[Event]) attach(containerPid uint32) {
	var attachedUUIDs []inodeUUID
	attachFilePaths := searchForLibrary(containerPid, t.attachFilePath)

	for _, filePath := range attachFilePaths {
		file, err := os.Open(filePath)
		if err != nil {
			continue
		}

		// get fsID of the executable
		fsStat := unix.Statfs_t{}
		err = unix.Fstatfs(int(file.Fd()), &fsStat)
		if err != nil {
			file.Close()
			continue
		}

		// get inode ID of the executable
		stat := unix.Stat_t{}
		err = unix.Fstat(int(file.Fd()), &stat)
		if err != nil {
			file.Close()
			continue
		}

		fileUUID := inodeUUID{fsStat.Fsid, stat.Ino}
		attachedUUIDs = append(attachedUUIDs, fileUUID)
		fmt.Printf("[DEBUG] attach: fsID: [%d %d], ino: %d, dev: %d, rdev:%d\n", fsStat.Fsid.Val[0], fsStat.Fsid.Val[1], stat.Ino, stat.Dev, stat.Rdev)

		inode, exists := t.inodeRefCount[fileUUID]
		if !exists {
			// TODO: remove these `[DEBUG]` info if stable
			fmt.Println("[DEBUG] attaching uprobe to: ", filePath)
			progLink, _ := t.attachEbpf(file)
			if progLink == nil {
				fmt.Println("[DEBUG] attach uprobe ebpf failed")
			}
			t.inodeRefCount[fileUUID] = &inodeKeeper{1, file, progLink}
		} else {
			inode.counter++
			file.Close()
		}
	}

	t.containerPid2Inode[containerPid] = attachedUUIDs
}

// AttachContainer will attach now if the prog is ready, otherwise it will add container into the pending list
func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.prog == nil {
		_, exist := t.pendingContainerPids[container.Pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", container.Pid)
		}
		t.pendingContainerPids[container.Pid] = true
	} else {
		_, exist := t.containerPid2Inode[container.Pid]
		if exist {
			return fmt.Errorf("container PID already exists: %d", container.Pid)
		}
		t.attach(container.Pid)
	}
	return nil
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	containerPID := container.Pid

	if t.prog == nil {
		// remove from pending list
		_, exist := t.pendingContainerPids[containerPID]
		if !exist {
			return fmt.Errorf("container PID does not exist in pending list")
		}
		delete(t.pendingContainerPids, containerPID)
	} else {
		// detach from container if attached
		attachedUUIDs, exist := t.containerPid2Inode[containerPID]
		if !exist {
			return nil
		}
		// remove containerPID form containerPid2Inode
		delete(t.containerPid2Inode, containerPID)

		for _, attachedUUID := range attachedUUIDs {
			keeper, exist := t.inodeRefCount[attachedUUID]
			if !exist {
				return fmt.Errorf("internal error: finding inodeKeeper with inodeUUID")
			}
			keeper.counter--
			if keeper.counter == 0 {
				keeper.close()
				delete(t.inodeRefCount, attachedUUID)
			}
		}
	}

	return nil
}

func (t *Tracer[Event]) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, keeper := range t.inodeRefCount {
		keeper.close()
	}

	t.closed = true
}
