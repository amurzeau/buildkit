package integration

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
)

func InitContainerdWorker() {
	Register(&containerd{
		name:       "containerd",
		containerd: "containerd",
	})
	// defined in Dockerfile
	// e.g. `containerd-1.1=/opt/containerd-1.1/bin,containerd-42.0=/opt/containerd-42.0/bin`
	if s := os.Getenv("BUILDKIT_INTEGRATION_CONTAINERD_EXTRA"); s != "" {
		entries := strings.Split(s, ",")
		for _, entry := range entries {
			pair := strings.Split(strings.TrimSpace(entry), "=")
			if len(pair) != 2 {
				panic(errors.Errorf("unexpected BUILDKIT_INTEGRATION_CONTAINERD_EXTRA: %q", s))
			}
			name, bin := pair[0], pair[1]
			Register(&containerd{
				name:       name,
				containerd: filepath.Join(bin, "containerd"),
				// override PATH to make sure that the expected version of the shim binary is used
				extraEnv: []string{fmt.Sprintf("PATH=%s:%s", bin, os.Getenv("PATH"))},
			})
		}
	}

	// the rootless uid is defined in Dockerfile
	if s := os.Getenv("BUILDKIT_INTEGRATION_ROOTLESS_IDPAIR"); s != "" {
		var uid, gid int
		if _, err := fmt.Sscanf(s, "%d:%d", &uid, &gid); err != nil {
			bklog.L.Fatalf("unexpected BUILDKIT_INTEGRATION_ROOTLESS_IDPAIR: %q", s)
		}
		if rootlessSupported(uid) {
			Register(&containerd{
				name:        "containerd-rootless",
				containerd:  "containerd",
				uid:         uid,
				gid:         gid,
				snapshotter: "native",
			})
			Register(&containerd{
				name:        "containerd-rootless-snapshotter-fuse-overlayfs",
				containerd:  "containerd",
				uid:         uid,
				gid:         gid,
				snapshotter: "fuse-overlayfs",
			})
		}
	}

	if s := os.Getenv("BUILDKIT_INTEGRATION_SNAPSHOTTER"); s != "" {
		Register(&containerd{
			name:        fmt.Sprintf("containerd-snapshotter-%s", s),
			containerd:  "containerd",
			snapshotter: s,
		})
	}
}

type containerd struct {
	name        string
	containerd  string
	snapshotter string
	uid         int
	gid         int
	extraEnv    []string // e.g. "PATH=/opt/containerd-1.4/bin:/usr/bin:..."
}

func (c *containerd) Name() string {
	return c.name
}

func (c *containerd) Rootless() bool {
	return c.uid != 0
}

func (c *containerd) New(ctx context.Context, cfg *BackendConfig) (b Backend, cl func() error, err error) {
	if err := lookupBinary(c.containerd); err != nil {
		return nil, nil, err
	}
	if err := lookupBinary("buildkitd"); err != nil {
		return nil, nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, nil, err
	}

	deferF := &multiCloser{}
	cl = deferF.F()

	defer func() {
		if err != nil {
			deferF.F()()
			cl = nil
		}
	}()

	rootless := false
	if c.uid != 0 {
		if c.gid == 0 {
			return nil, nil, errors.Errorf("unsupported id pair: uid=%d, gid=%d", c.uid, c.gid)
		}
		rootless = true
	}

	tmpdir, err := os.MkdirTemp("", "bktest_containerd")
	if err != nil {
		return nil, nil, err
	}
	if rootless {
		if err := os.Chown(tmpdir, c.uid, c.gid); err != nil {
			return nil, nil, err
		}
	}

	deferF.append(func() error { return os.RemoveAll(tmpdir) })

	// Run rootlesskit if rootless mode
	rootlessKitState := ""
	if rootless {
		rootlessKitState, err = c.runRootlesskit(tmpdir, cfg, deferF)
		if err != nil {
			return nil, nil, err
		}
	}

	// Generate containerd config file
	address := filepath.Join(tmpdir, "containerd.sock")
	config := fmt.Sprintf(`root = %q
state = %q
# CRI plugins listens on 10010/tcp for stream server.
# We disable CRI plugin so that multiple instance can run simultaneously.
disabled_plugins = ["cri"]

[grpc]
  address = %q

[debug]
  level = "debug"
  address = %q
`, filepath.Join(tmpdir, "root"), filepath.Join(tmpdir, "state"), address, filepath.Join(tmpdir, "debug.sock"))

	var snBuildkitdArgs []string
	if c.snapshotter != "" {
		snBuildkitdArgs = append(snBuildkitdArgs,
			fmt.Sprintf("--containerd-worker-snapshotter=%s", c.snapshotter))

		// Start snapshotter plugin
		if err := c.runSnapshotterPlugin(&config, cfg, rootlessKitState, deferF); err != nil {
			return nil, nil, err
		}
	} else if rootless {
		snBuildkitdArgs = append(snBuildkitdArgs, "--containerd-worker-snapshotter=native")
	}

	// Write containerd config file
	configFile := filepath.Join(tmpdir, "config.toml")
	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		return nil, nil, err
	}

	// Start containerd
	containerdArgs := []string{c.containerd, "--config", configFile}
	err = c.runContainerdProcess(cfg, rootlessKitState, containerdArgs, address, c.extraEnv, deferF)
	if err != nil {
		return nil, nil, err
	}

	buildkitdArgs := append([]string{"buildkitd",
		"--oci-worker=false",
		"--containerd-worker-gc=false",
		"--containerd-worker=true",
		"--containerd-worker-addr", address,
		"--containerd-worker-labels=org.mobyproject.buildkit.worker.sandbox=true", // Include use of --containerd-worker-labels to trigger https://github.com/moby/buildkit/pull/603
	}, snBuildkitdArgs...)

	if runtime.GOOS != "windows" && c.snapshotter != "native" {
		c.extraEnv = append(c.extraEnv, "BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF=true")
	}
	if rootless {
		buildkitdArgs, err = addRootlessArgs(buildkitdArgs, c.uid, rootlessKitState)
		if err != nil {
			return nil, nil, err
		}
	}
	buildkitdSock, stop, err := runBuildkitd(ctx, cfg, buildkitdArgs, cfg.Logs, c.uid, c.gid, c.extraEnv)
	if err != nil {
		printLogs(cfg.Logs, log.Println)
		return nil, nil, err
	}
	deferF.append(stop)

	return backend{
		address:           buildkitdSock,
		containerdAddress: address,
		rootless:          rootless,
		snapshotter:       c.snapshotter,
	}, cl, nil
}

func (c *containerd) runRootlesskit(tmpdir string, cfg *BackendConfig, deferF *multiCloser) (string, error) {
	rootlessKitState := filepath.Join(tmpdir, "rootlesskit-containerd")
	args := append(append([]string{"sudo", "-u", fmt.Sprintf("#%d", c.uid), "-i"}, c.extraEnv...),
		"rootlesskit",
		fmt.Sprintf("--state-dir=%s", rootlessKitState),
		// Integration test requires the access to localhost of the host network namespace.
		// TODO: remove these configurations
		"--net=host",
		"--disable-host-loopback",
		"--port-driver=none",
		"--copy-up=/etc",
		"--copy-up=/run",
		"--copy-up=/var/lib",
		"--propagation=rslave",
		"--slirp4netns-sandbox=auto",
		"--slirp4netns-seccomp=auto",
		"--mtu=0",
		"sh",
		"-c",
		"rm -rf /run/containerd ; sleep infinity")

	// Start rootlesskit
	// Don't put rootlessKitState as we are just starting rootlesskit, rootlessKitState won't contain child_pid
	err := c.runContainerdProcess(cfg, "", args, filepath.Join(rootlessKitState, "api.sock"), nil, deferF)
	if err != nil {
		return "", err
	}

	return rootlessKitState, nil
}

func (c *containerd) runSnapshotterPlugin(config *string, cfg *BackendConfig, rootlessKitState string, deferF *multiCloser) error {
	var argsGenerator func(string, string) []string
	switch c.snapshotter {
	case "stargz":
		argsGenerator = func(snPath string, snRoot string) []string {
			return []string{"containerd-stargz-grpc",
				"--log-level", "debug",
				"--address", snPath,
				"--root", snRoot,
			}
		}
	case "fuse-overlayfs":
		argsGenerator = func(snPath string, snRoot string) []string {
			return []string{"containerd-fuse-overlayfs-grpc", snPath, snRoot}
		}
	default:
		// No plugin to run
		return nil
	}

	snapshotterTmpDir, err := os.MkdirTemp("", fmt.Sprintf("bktest_containerd-%s-grpc", c.snapshotter))
	if err != nil {
		return err
	}
	deferF.append(func() error { return os.RemoveAll(snapshotterTmpDir) })

	if err := os.Chown(snapshotterTmpDir, c.uid, c.gid); err != nil {
		return err
	}

	snPath := filepath.Join(snapshotterTmpDir, "snapshotter.sock")
	snRoot := filepath.Join(snapshotterTmpDir, "root")
	*config = c.generateSnapshotterConfig(*config, snPath)

	args := argsGenerator(snPath, snRoot)
	if err := lookupBinary(args[0]); err != nil {
		return err
	}

	err = c.runContainerdProcess(cfg, rootlessKitState, args, snPath, nil, deferF)
	if err != nil {
		return err
	}

	return nil
}

func (c *containerd) generateSnapshotterConfig(config string, snPath string) string {
	return fmt.Sprintf(`%s

[proxy_plugins]
	[proxy_plugins.%s]
	type = "snapshot"
	address = %q
`, config, c.snapshotter, snPath)
}

func formatLogs(m map[string]*bytes.Buffer) string {
	var ss []string
	for k, b := range m {
		if b != nil {
			ss = append(ss, fmt.Sprintf("%q:%q", k, b.String()))
		}
	}
	return strings.Join(ss, ",")
}

func (c *containerd) runContainerdProcess(cfg *BackendConfig, rootlessKitState string, args []string, unixSocketToWait string, extraEnv []string, deferF *multiCloser) error {
	// If we are using rootlesskit, add arguments to run the process in rootless namespace
	if rootlessKitState != "" {
		var err error
		args, err = addRootlessArgs(args, c.uid, rootlessKitState)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(args[0], args[1:]...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	snStop, err := startCmd(cmd, cfg.Logs)
	if err != nil {
		return err
	}
	if err := waitUnix(unixSocketToWait, 10*time.Second, cmd); err != nil {
		snStop()
		return errors.Wrapf(err, "%s did not start up: %s", cmd.Path, formatLogs(cfg.Logs))
	}
	deferF.append(snStop)

	return nil
}

func addRootlessArgs(args []string, uid int, rootlessKitState string) ([]string, error) {
	pidStr, err := os.ReadFile(filepath.Join(rootlessKitState, "child_pid"))
	if err != nil {
		return args, err
	}
	pid, err := strconv.ParseInt(string(pidStr), 10, 64)
	if err != nil {
		return args, err
	}
	args = append([]string{"sudo", "-u", fmt.Sprintf("#%d", uid), "-i", "--", "exec",
		"nsenter", "-U", "--preserve-credentials", "-m", "-t", fmt.Sprintf("%d", pid)},
		args...)

	return args, nil
}
