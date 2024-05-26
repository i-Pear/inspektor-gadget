/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 *
 * This is refactored to be used as a library
 * Original source code: https://github.com/elastic/otel-profiling-agent/blob/main/libpf/nativeunwind
 */

package ustackunwinder

import (
	"fmt"

	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/elfunwindinfo"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
)

func main() {
	interval := sdtypes.IntervalData{}
	err := elfunwindinfo.Extract("/usr/lib/libstdc++.so.6", &interval)
	if err != nil {
		fmt.Println(err.Error())
	}

	for _, i := range interval.Deltas {
		fmt.Println(i.Info)
	}
}
