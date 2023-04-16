package overlay

import (
	"strings"

	"github.com/containerd/containerd/mount"
)

// IsOverlayMountType returns true if the mount type is overlay or fuse-overlayfs
func IsOverlayMountType(mnt mount.Mount) bool {
	return mnt.Type == "overlay" || strings.HasPrefix(mnt.Type, "fuse3.")
}
