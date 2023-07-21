// Copyright 2023 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

func TestRunTraceOpen(t *testing.T) {
	ns := GenerateTestNamespaceName("test-run-trace-open")

	t.Parallel()

	prog := "../../gadgets/trace_open_x86.bpf.o"

	// TODO: Handle it once we support getting container image name from docker
	errIsDocker, isDockerRuntime := IsDockerRuntime()
	if errIsDocker != nil {
		t.Fatalf("checking if docker is current runtime: %v", errIsDocker)
	}

	if *k8sArch == "arm64" {
		prog = "../../gadgets/trace_open_arm64.bpf.o"
	}

	const (
		def = "../../gadgets/trace_open.yaml"
	)

	traceOpenCmd := &Command{
		Name:         "StartRunTraceOpenGadget",
		Cmd:          fmt.Sprintf("$KUBECTL_GADGET run --prog @%s --definition @%s -n %s -o json", prog, def, ns),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedBaseJsonObj := RunEventToObj(t, &types.Event{
				Event: BuildBaseEvent(ns, WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime)),
			})

			expectedTraceOpenJsonObj := map[string]interface{}{
				"comm":     "cat",
				"fname":    "/dev/null",
				"uid":      1000,
				"gid":      1111,
				"ret":      3,
				"flags":    0,
				"mntns_id": 0,
				"pid":      0,
			}

			expectedJsonObj := MergeJsonObjs(t, expectedBaseJsonObj, expectedTraceOpenJsonObj)

			normalize := func(m map[string]interface{}) {
				SetEventTimestamp(m, 0)
				SetEventMountNsID(m, 0)

				SetEventK8sNode(m, "")

				// TODO: Verify container runtime and container name
				SetEventRuntimeName(m, "")
				SetEventRuntimeContainerID(m, "")
				SetEventRuntimeContainerName(m, "")

				m["pid"] = uint32(0)
				m["mntns_id"] = uint64(0)
			}

			return ExpectEntriesToMatchObj(t, output, normalize, expectedJsonObj)
		},
	}

	commands := []*Command{
		CreateTestNamespaceCommand(ns),
		traceOpenCmd,
		BusyboxPodRepeatCommand(ns, "setuidgid 1000:1111 cat /dev/null"),
		WaitUntilTestPodReadyCommand(ns),
		DeleteTestNamespaceCommand(ns),
	}

	RunTestSteps(commands, t, WithCbBeforeCleanup(PrintLogsFn(ns)))
}