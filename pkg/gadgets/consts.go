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

package gadgets

const (
	PinPath = "/sys/fs/bpf/gadget"

	PerfBufferPages = 64

	// Constant used to enable filtering by mount namespace inode id in eBPF.
	// Keep in syn with variable defined in include/gadget/mntns_filter.h.
	FilterByMntNsName = "gadget_filter_by_mntns"

	// Name of the map that stores the mount namespace inode id to filter on.
	// Keep in syn with name used in include/gadget/mntns_filter.h.
	MntNsFilterMapName = "gadget_mntns_filter_map"
)
