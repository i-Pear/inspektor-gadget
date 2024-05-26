/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 *
 * This is refactored to be used as a library
 * Original source code: https://github.com/elastic/otel-profiling-agent/blob/main/libpf/process/process.go
 */

package ustackunwinder

import (
	"bufio"
	"debug/elf"
	"io"
	"strings"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/process"
	"github.com/elastic/otel-profiling-agent/libpf/stringutil"
)

func trimMappingPath(path string) string {
	// Trim the deleted indication from the path.
	// See path_with_deleted in linux/fs/d_path.c
	path = strings.TrimSuffix(path, " (deleted)")
	if path == "/dev/zero" {
		// Some JIT engines map JIT area from /dev/zero
		// make it anonymous.
		return ""
	}
	return path
}

func parseMappings(mapsFile io.Reader) ([]process.Mapping, error) {
	mappings := make([]process.Mapping, 0)
	scanner := bufio.NewScanner(mapsFile)
	buf := make([]byte, 512)
	scanner.Buffer(buf, 8192)
	for scanner.Scan() {
		var fields [6]string
		var addrs [2]string
		var devs [2]string

		line := stringutil.ByteSlice2String(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			continue
		}
		if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
			continue
		}

		mapsFlags := fields[1]
		if len(mapsFlags) < 3 {
			continue
		}
		flags := elf.ProgFlag(0)
		if mapsFlags[0] == 'r' {
			flags |= elf.PF_R
		}
		if mapsFlags[1] == 'w' {
			flags |= elf.PF_W
		}
		if mapsFlags[2] == 'x' {
			flags |= elf.PF_X
		}

		// Ignore non-executable mappings
		if flags&elf.PF_X == 0 {
			continue
		}
		inode := libpf.DecToUint64(fields[4])
		path := fields[5]
		if stringutil.SplitN(fields[3], ":", devs[:]) < 2 {
			continue
		}
		device := libpf.HexToUint64(devs[0])<<8 + libpf.HexToUint64(devs[1])

		if inode == 0 {
			continue
		} else {
			path = trimMappingPath(path)
			path = strings.Clone(path)
		}

		vaddr := libpf.HexToUint64(addrs[0])
		mappings = append(mappings, process.Mapping{
			Vaddr:      vaddr,
			Length:     libpf.HexToUint64(addrs[1]) - vaddr,
			Flags:      flags,
			FileOffset: libpf.HexToUint64(fields[2]),
			Device:     device,
			Inode:      inode,
			Path:       path,
		})
	}
	return mappings, scanner.Err()
}
