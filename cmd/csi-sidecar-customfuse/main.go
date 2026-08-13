/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// csi-sidecar-customfuse runs the CSI node server for the generic FUSE
// driver inside the sandbox csi-sidecar container. It listens on the
// per-driver socket that the storage CLI dials, and forwards mount requests
// to mount-proxy-server (which runs the FUSE entrypoint).
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/openkruise/agents/pkg/agent-runtime/customfusesidecar"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"
)

var (
	csiSocketPath = flag.String("csi-socket", "/var/run/csi/sockets/customfuseplugin.csi.alibabacloud.com/csi.sock",
		"path of the CSI node server socket that the storage CLI dials")
	proxySocketPath = flag.String("proxy-socket", "/var/run/csi/mounter.sock",
		"path of the mount-proxy-server socket")
)

func main() {
	klog.InitFlags(flag.CommandLine)
	flag.Parse()

	if err := run(); err != nil {
		klog.ErrorS(err, "csi-sidecar-customfuse exited with error")
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll(filepath.Dir(*csiSocketPath), 0o755); err != nil {
		return err
	}
	// A stale socket from a previous run would make Listen fail with
	// EADDRINUSE. The mount namespace is fresh per sandbox, so removing any
	// pre-existing file is safe.
	if err := os.Remove(*csiSocketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	lis, err := net.Listen("unix", *csiSocketPath)
	if err != nil {
		return err
	}
	defer lis.Close()

	srv := grpc.NewServer()
	csi.RegisterNodeServer(srv, customfusesidecar.NewNodeServer(*proxySocketPath))
	log.Printf("csi-sidecar-customfuse listening on %s, forwarding to %s", *csiSocketPath, *proxySocketPath)

	go func() {
		if err := srv.Serve(lis); err != nil {
			klog.ErrorS(err, "gRPC server failed")
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	srv.GracefulStop()
	return nil
}
