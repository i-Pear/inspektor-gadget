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

// TODO: The current implementation doesn't consider any filtering

// We hold fd(s) of the executables, so we can use `/proc/self/fd/...` for attaching, it is used to avoid fd-reusing
// We open the executables at attachContainer event, so if the file changed before the ebpf program loads,
// we will still attach to the origin executable.

// We are not maintaining ebpf.collection or perf-ring buffer by ourselves, it's hold by the parent tracer

// All interfaces should hold lock, and inner functions do not

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
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type inodeKeeper struct {
	// if an inodeKeeper exists, `file` must be available, but `link` may be nil
	// so if a inode is proved to not having right symbol, we can skip it for the next time
	counter int
	file    *os.File
	link    link.Link
}

func (t *inodeKeeper) close() {
	t.file.Close()
	if t.link != nil {
		t.link.Close()
	}
}

type Tracer[Event any] struct {
	progName       string
	progType       string
	attachFilePath string
	attachSymbol   string
	prog           *ebpf.Program

	ctrPid2FsId    map[uint32]unix.Fsid
	inodeRefCount  map[unix.Fsid]*inodeKeeper
	pendingCtrPids map[uint32]bool

	closed bool

	mu sync.Mutex
}

func NewTracer[Event any]() (_ *Tracer[Event], err error) {
	t := &Tracer[Event]{
		ctrPid2FsId:    make(map[uint32]unix.Fsid),
		inodeRefCount:  make(map[unix.Fsid]*inodeKeeper),
		pendingCtrPids: make(map[uint32]bool),
		closed:         false,
	}
	return t, nil
}

func (t *Tracer[Event]) attachProgToInode(file *os.File) (link.Link, error) {
	// attach ebpf program to self-hosted inode, used by `Attach()`

	attachPath := path.Join(host.HostProcFs, "self/fd/", fmt.Sprint(file.Fd()))
	ex, err := link.OpenExecutable(attachPath)
	if err != nil {
		return nil, fmt.Errorf("opening executable: %q", attachPath)
	}
	switch t.progType {
	case "uprobe":
		return ex.Uprobe(t.attachSymbol, t.prog, nil)
	case "uretprobe":
		return ex.Uretprobe(t.attachSymbol, t.prog, nil)
	default:
		return nil, fmt.Errorf("attaching to inode: unsupported prog type: %q", t.progType)
	}
}

func (t *Tracer[Event]) AttachProg(progName string, progType string, attachTo string, prog *ebpf.Program) error {
	// interface for outside, load ebpf program, and attach if there are pending containers

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
	if progType != "uprobe" && progType != "uretprobe" {
		return fmt.Errorf("unsupported uprobe prog type: %q", progType)
	}
	if strings.Contains(parts[0], "..") {
		return fmt.Errorf("'..' is not allowed to appear in the path")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.progName = progName
	t.progType = progType
	t.attachFilePath = parts[0]
	t.attachSymbol = parts[1]
	t.prog = prog

	// attach to pending inode, then release the pending list
	for pid := range t.pendingCtrPids {
		t.attach(pid)
	}
	t.pendingCtrPids = nil

	return nil
}

func searchForLibrary(containerPid uint32, path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Join(host.HostProcFs, fmt.Sprint(containerPid), "root", path), nil
	} else {
		// simulate the loader's behaviour
		// see https://github.com/lattera/glibc/blob/master/elf/cache.c#L187
		return "", fmt.Errorf("finding library %q", path)
	}
}

func (t *Tracer[Event]) attach(containerPid uint32) {
	// ! lock must be hold by caller
	// attach to a container NOW

	// open the executable which is going to be attached
	attachFilePath, err := searchForLibrary(containerPid, t.attachFilePath)
	if err != nil {
		return
	}
	file, err := os.Open(attachFilePath)
	if err != nil {
		return
	}

	// get fsID of the executable
	stat := unix.Statfs_t{}
	err = unix.Fstatfs(int(file.Fd()), &stat)
	if err != nil {
		return
	}
	fileFsID := stat.Fsid

	inode, exists := t.inodeRefCount[fileFsID]
	if !exists {
		progLink, _ := t.attachProgToInode(file)
		t.inodeRefCount[fileFsID] = &inodeKeeper{1, file, progLink}
	} else {
		inode.counter++
		err := file.Close()
		if err != nil {
			return
		}
	}

	t.ctrPid2FsId[containerPid] = fileFsID
}

func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	// interface for outside, if prog is ready, then attach now; otherwise add pid to pending list
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.prog == nil {
		// attach later
		t.pendingCtrPids[container.Pid] = true
	} else {
		// attach now
		t.attach(container.Pid)
	}

	// should not have errors
	return nil
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	containerPID := container.Pid
	// if we didn't find the right file, there isn't a fsID
	fsId, exist := t.ctrPid2FsId[containerPID]
	if !exist {
		return nil
	}
	keeper, exist := t.inodeRefCount[fsId]
	if !exist {
		return fmt.Errorf("finding inodeKeeper with fsId")
	}
	keeper.counter--
	if keeper.counter == 0 {
		keeper.close()
		delete(t.inodeRefCount, fsId)
	}

	// should not have errors
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
