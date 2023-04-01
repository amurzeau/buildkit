package integration

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/moby/buildkit/util/bklog"
	"github.com/pkg/errors"
)

func InitOCIWorker() {
	Register(&oci{})

	// the rootless uid is defined in Dockerfile
	if s := os.Getenv("BUILDKIT_INTEGRATION_ROOTLESS_IDPAIR"); s != "" {
		var uid, gid int
		if _, err := fmt.Sscanf(s, "%d:%d", &uid, &gid); err != nil {
			bklog.L.Fatalf("unexpected BUILDKIT_INTEGRATION_ROOTLESS_IDPAIR: %q", s)
		}
		if rootlessSupported(uid) {
			Register(&oci{
				uid: uid,
				gid: gid,
			})
			Register(&oci{
				uid:                    uid,
				gid:                    gid,
				snapshotter:            "fuse-overlayfs",
				fuseDisableOvlWhiteout: false,
			})
			Register(&oci{
				uid:                    uid,
				gid:                    gid,
				snapshotter:            "fuse-overlayfs",
				fuseDisableOvlWhiteout: true,
			})
		}
	}

	if s := os.Getenv("BUILDKIT_INTEGRATION_SNAPSHOTTER"); s != "" {
		Register(&oci{snapshotter: s})
	}
}

type oci struct {
	uid                    int
	gid                    int
	snapshotter            string
	fuseDisableOvlWhiteout bool
}

func (s *oci) Name() string {
	name := "oci"
	if s.uid != 0 {
		name += "-rootless"
	}
	if s.snapshotter != "" {
		name += fmt.Sprintf("-snapshotter-%s", s.snapshotter)
	}
	if s.fuseDisableOvlWhiteout {
		name += "-disable-ovl-whiteout"
	}
	return name
}

func (s *oci) Rootless() bool {
	return s.uid != 0
}

func (s *oci) New(ctx context.Context, cfg *BackendConfig) (Backend, func() error, error) {
	if err := lookupBinary("buildkitd"); err != nil {
		return nil, nil, err
	}
	if err := requireRoot(); err != nil {
		return nil, nil, err
	}
	// Include use of --oci-worker-labels to trigger https://github.com/moby/buildkit/pull/603
	buildkitdArgs := []string{"buildkitd", "--oci-worker=true", "--containerd-worker=false", "--oci-worker-gc=false", "--oci-worker-labels=org.mobyproject.buildkit.worker.sandbox=true"}

	if s.snapshotter != "" {
		buildkitdArgs = append(buildkitdArgs,
			fmt.Sprintf("--oci-worker-snapshotter=%s", s.snapshotter))
	}

	if s.uid != 0 {
		if s.gid == 0 {
			return nil, nil, errors.Errorf("unsupported id pair: uid=%d, gid=%d", s.uid, s.gid)
		}
		// TODO: make sure the user exists and subuid/subgid are configured.
		buildkitdArgs = append([]string{"sudo", "-u", fmt.Sprintf("#%d", s.uid), "-i", "--", "exec", "rootlesskit"}, buildkitdArgs...)
	}

	var extraEnv []string
	if runtime.GOOS != "windows" && s.snapshotter != "native" {
		extraEnv = append(extraEnv, "BUILDKIT_DEBUG_FORCE_OVERLAY_DIFF=true")
	}
	if s.fuseDisableOvlWhiteout {
		extraEnv = append(extraEnv, "FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT=1")
	}
	buildkitdSock, stop, err := runBuildkitd(ctx, cfg, buildkitdArgs, cfg.Logs, s.uid, s.gid, extraEnv)
	if err != nil {
		printLogs(cfg.Logs, log.Println)
		return nil, nil, err
	}

	return backend{
		address:     buildkitdSock,
		rootless:    s.uid != 0,
		snapshotter: s.snapshotter,
	}, stop, nil
}
