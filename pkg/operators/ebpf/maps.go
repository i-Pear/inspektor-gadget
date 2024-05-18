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

package ebpfoperator

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} kernelstackhelper ./bpf/kernel_stack.bpf.c -- -I./bpf/

var (
	kernelStackExtensionSpec *ebpf.CollectionSpec
)

func (i *ebpfInstance) populateMap(t btf.Type, varName string) error {
	i.logger.Debugf("populating map %q", varName)

	newVar := &ebpfVar{
		name:    varName,
		refType: reflect.TypeOf(&ebpf.Map{}),
		tags:    nil,
	}

	i.vars[varName] = newVar

	// Set variable to nil pointer to map, so it's present
	var nilVal *ebpf.Map
	i.gadgetCtx.SetVar(varName, nilVal)
	return nil
}

func (i *ebpfInstance) getKernelStackMap() (*ebpf.Map, error) {
	if i.kernelStackIdMap != nil {
		return i.kernelStackIdMap, nil
	}

	stackIdMapSpec := ebpf.MapSpec{
		Name:       kernelStackMapName,
		Type:       ebpf.StackTrace,
		KeySize:    4,
		ValueSize:  8 * perfMaxStackDepth,
		MaxEntries: kernelStackMapMaxEntries,
	}
	var err error
	i.kernelStackIdMap, err = ebpf.NewMap(&stackIdMapSpec)
	if err != nil {
		return nil, fmt.Errorf("creating kernel stack map: %w", err)
	}
	return i.kernelStackIdMap, nil

}

func needKernelStackExtension(target *ebpf.Program) bool {
	btfHandle, err := target.Handle()
	if err != nil {
		return false
	}
	defer btfHandle.Close()

	spec, err := btfHandle.Spec(nil)
	if err != nil {
		return false
	}

	var function *btf.Func
	err = spec.TypeByName(kernelStackFuncName, &function)
	return err == nil
}

func (i *ebpfInstance) loadKernelStackExtensionIfRequired(target *ebpf.Program) (link.Link, error) {
	if !needKernelStackExtension(target) {
		return nil, nil
	}
	// load extension spec
	if kernelStackExtensionSpec == nil {
		var err error
		kernelStackExtensionSpec, err = loadKernelstackhelper()
		if err != nil {
			return nil, fmt.Errorf("loading kernel stack extension spec: %w", err)
		}
	}
	extensionSpec := kernelStackExtensionSpec.Copy()

	// bind attach target
	extensionProgramSpec, exist := extensionSpec.Programs[kernelStackFuncName]
	if !exist {
		return nil, errors.New("kernel stack extension spec not exist")
	}
	extensionProgramSpec.AttachTarget = target

	// rewrite kernel stack map and load extension program
	kernelStackMap, err := i.getKernelStackMap()
	if err != nil {
		return nil, err
	}
	mapReplacements := map[string]*ebpf.Map{
		kernelStackMapName: kernelStackMap,
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	collection, err := ebpf.NewCollectionWithOptions(extensionSpec, opts)
	if err != nil {
		return nil, fmt.Errorf("loading kernel stack extension: %w", err)
	}
	defer collection.Close()

	extensionProgram, exist := collection.Programs[kernelStackFuncName]
	if !exist {
		return nil, errors.New("kernel stack extension program not found")
	}
	extensionLink, err := link.AttachFreplace(target, kernelStackFuncName, extensionProgram)
	if err != nil {
		return nil, fmt.Errorf("replacing function %q: %w", kernelStackFuncName, err)
	}

	return extensionLink, nil
}
