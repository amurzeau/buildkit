//go:build !windows
// +build !windows

package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/snapshots/overlay/overlayutils"
	"github.com/containerd/continuity/fs"
	"github.com/hashicorp/go-multierror"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/moby/buildkit/util/overlay"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// diffApply applies the provided diffs to the dest Mountable and returns the correctly calculated disk usage
// that accounts for any hardlinks made from existing snapshots. ctx is expected to have a temporary lease
// associated with it.
func (sn *mergeSnapshotter) diffApply(ctx context.Context, dest Mountable, diffs ...Diff) (_ snapshots.Usage, rerr error) {
	a, err := applierFor(dest, sn.tryCrossSnapshotLink, sn.witheoutType)
	if err != nil {
		return snapshots.Usage{}, errors.Wrapf(err, "failed to create applier")
	}
	defer func() {
		releaseErr := a.Release()
		if releaseErr != nil {
			rerr = multierror.Append(rerr, errors.Wrapf(releaseErr, "failed to release applier")).ErrorOrNil()
		}
	}()

	// TODO:(sipsma) optimization: parallelize differ and applier in separate goroutines, connected with a buffered channel

	for _, diff := range diffs {
		var lowerMntable Mountable
		if diff.Lower != "" {
			if info, err := sn.Stat(ctx, diff.Lower); err != nil {
				return snapshots.Usage{}, errors.Wrapf(err, "failed to stat lower snapshot %s", diff.Lower)
			} else if info.Kind == snapshots.KindCommitted {
				lowerMntable, err = sn.View(ctx, identity.NewID(), diff.Lower)
				if err != nil {
					return snapshots.Usage{}, errors.Wrapf(err, "failed to mount lower snapshot view %s", diff.Lower)
				}
			} else {
				lowerMntable, err = sn.Mounts(ctx, diff.Lower)
				if err != nil {
					return snapshots.Usage{}, errors.Wrapf(err, "failed to mount lower snapshot %s", diff.Lower)
				}
			}
		}
		var upperMntable Mountable
		if diff.Upper != "" {
			if info, err := sn.Stat(ctx, diff.Upper); err != nil {
				return snapshots.Usage{}, errors.Wrapf(err, "failed to stat upper snapshot %s", diff.Upper)
			} else if info.Kind == snapshots.KindCommitted {
				upperMntable, err = sn.View(ctx, identity.NewID(), diff.Upper)
				if err != nil {
					return snapshots.Usage{}, errors.Wrapf(err, "failed to mount upper snapshot view %s", diff.Upper)
				}
			} else {
				upperMntable, err = sn.Mounts(ctx, diff.Upper)
				if err != nil {
					return snapshots.Usage{}, errors.Wrapf(err, "failed to mount upper snapshot %s", diff.Upper)
				}
			}
		} else {
			// create an empty view
			upperMntable, err = sn.View(ctx, identity.NewID(), "")
			if err != nil {
				return snapshots.Usage{}, errors.Wrapf(err, "failed to mount empty upper snapshot view %s", diff.Upper)
			}
		}
		d, err := differFor(lowerMntable, upperMntable)
		if err != nil {
			return snapshots.Usage{}, errors.Wrapf(err, "failed to create differ")
		}
		defer func() {
			rerr = multierror.Append(rerr, d.Release()).ErrorOrNil()
		}()
		if err := d.HandleChanges(ctx, a.Apply); err != nil {
			return snapshots.Usage{}, errors.Wrapf(err, "failed to handle changes")
		}
	}

	if err := a.Flush(); err != nil {
		return snapshots.Usage{}, errors.Wrapf(err, "failed to flush changes")
	}
	return a.Usage()
}

type change struct {
	kind    fs.ChangeKind
	subPath string
	srcPath string
	srcStat *syscall.Stat_t
	// linkSubPath is set to a subPath of a previous change from the same
	// differ instance that is a hardlink to this one, if any.
	linkSubPath string
}

type inode struct {
	ino uint64
	dev uint64
}

func statInode(stat *syscall.Stat_t) inode {
	if stat == nil {
		return inode{}
	}
	return inode{
		ino: stat.Ino,
		dev: stat.Dev,
	}
}

type differ struct {
	lowerRoot    string
	releaseLower func() error

	upperRoot    string
	releaseUpper func() error

	upperBindSource  string
	upperOverlayDirs []string // ordered lowest -> highest

	upperdir string

	visited map[string]struct{} // set of parent subPaths that have been visited
	inodes  map[inode]string    // map of inode -> subPath
}

func differFor(lowerMntable, upperMntable Mountable) (_ *differ, rerr error) {
	d := &differ{
		visited: make(map[string]struct{}),
		inodes:  make(map[inode]string),
	}
	defer func() {
		if rerr != nil {
			rerr = multierror.Append(rerr, d.Release()).ErrorOrNil()
		}
	}()

	var lowerMnts []mount.Mount
	if lowerMntable != nil {
		mnts, release, err := lowerMntable.Mount()
		if err != nil {
			return nil, err
		}
		mounter := LocalMounterWithMounts(mnts)
		root, err := mounter.Mount()
		if err != nil {
			return nil, err
		}
		d.lowerRoot = root
		lowerMnts = mnts
		d.releaseLower = func() error {
			err := mounter.Unmount()
			return multierror.Append(err, release()).ErrorOrNil()
		}
	}

	var upperMnts []mount.Mount
	if upperMntable != nil {
		mnts, release, err := upperMntable.Mount()
		if err != nil {
			return nil, err
		}
		mounter := LocalMounterWithMounts(mnts)
		root, err := mounter.Mount()
		if err != nil {
			return nil, err
		}
		d.upperRoot = root
		upperMnts = mnts
		d.releaseUpper = func() error {
			err := mounter.Unmount()
			return multierror.Append(err, release()).ErrorOrNil()
		}
	}

	if len(upperMnts) == 1 {
		if upperMnts[0].Type == "bind" || upperMnts[0].Type == "rbind" {
			d.upperBindSource = upperMnts[0].Source
		} else if overlay.IsOverlayMountType(upperMnts[0]) {
			overlayDirs, err := overlay.GetOverlayLayers(upperMnts[0])
			if err != nil {
				return nil, errors.Wrapf(err, "failed to get overlay layers from mount %+v", upperMnts[0])
			}
			d.upperOverlayDirs = overlayDirs
		}
	}
	if len(lowerMnts) > 0 {
		if upperdir, err := overlay.GetUpperdir(lowerMnts, upperMnts); err == nil {
			d.upperdir = upperdir
		}
	}

	return d, nil
}

func (d *differ) HandleChanges(ctx context.Context, handle func(context.Context, *change) error) error {
	if d.upperdir != "" {
		return d.overlayChanges(ctx, handle)
	}
	return d.doubleWalkingChanges(ctx, handle)
}

func (d *differ) doubleWalkingChanges(ctx context.Context, handle func(context.Context, *change) error) error {
	return fs.Changes(ctx, d.lowerRoot, d.upperRoot, func(kind fs.ChangeKind, subPath string, srcfi os.FileInfo, prevErr error) error {
		if prevErr != nil {
			return prevErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if kind == fs.ChangeKindUnmodified {
			return nil
		}

		// NOTE: it's tempting to skip creating parent dirs when change kind is Delete, but
		// that would make us incompatible with the image exporter code:
		// https://github.com/containerd/containerd/pull/2095
		if err := d.checkParent(ctx, subPath, handle); err != nil {
			return errors.Wrapf(err, "failed to check parent for %s", subPath)
		}

		c := &change{
			kind:    kind,
			subPath: subPath,
		}

		if srcfi != nil {
			// Try to ensure that srcPath and srcStat are set to a file from the underlying filesystem
			// rather than the actual mount when possible. This allows hardlinking without getting EXDEV.
			switch {
			case !srcfi.IsDir() && d.upperBindSource != "":
				srcPath, err := safeJoin(d.upperBindSource, c.subPath)
				if err != nil {
					return errors.Wrapf(err, "failed to join %s and %s", d.upperBindSource, c.subPath)
				}
				c.srcPath = srcPath
				if fi, err := os.Lstat(c.srcPath); err == nil {
					srcfi = fi
				} else {
					return errors.Wrap(err, "failed to stat underlying file from bind mount")
				}
			case !srcfi.IsDir() && len(d.upperOverlayDirs) > 0:
				for i := range d.upperOverlayDirs {
					dir := d.upperOverlayDirs[len(d.upperOverlayDirs)-1-i]
					path, err := safeJoin(dir, c.subPath)
					if err != nil {
						return errors.Wrapf(err, "failed to join %s and %s", dir, c.subPath)
					}
					if stat, err := os.Lstat(path); err == nil {
						c.srcPath = path
						srcfi = stat
						break
					} else if errors.Is(err, unix.ENOENT) {
						continue
					} else {
						return errors.Wrap(err, "failed to lstat when finding direct path of overlay file")
					}
				}
			default:
				srcPath, err := safeJoin(d.upperRoot, subPath)
				if err != nil {
					return errors.Wrapf(err, "failed to join %s and %s", d.upperRoot, subPath)
				}
				c.srcPath = srcPath
				if fi, err := os.Lstat(c.srcPath); err == nil {
					srcfi = fi
				} else {
					return errors.Wrap(err, "failed to stat srcPath from differ")
				}
			}

			var ok bool
			c.srcStat, ok = srcfi.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.Errorf("unhandled stat type for %+v", srcfi)
			}

			if !srcfi.IsDir() && c.srcStat.Nlink > 1 {
				if linkSubPath, ok := d.inodes[statInode(c.srcStat)]; ok {
					c.linkSubPath = linkSubPath
				} else {
					d.inodes[statInode(c.srcStat)] = c.subPath
				}
			}
		}

		return handle(ctx, c)
	})
}

func (d *differ) overlayChanges(ctx context.Context, handle func(context.Context, *change) error) error {
	return overlay.Changes(ctx, func(kind fs.ChangeKind, subPath string, srcfi os.FileInfo, prevErr error) error {
		if prevErr != nil {
			return prevErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if kind == fs.ChangeKindUnmodified {
			return nil
		}

		if err := d.checkParent(ctx, subPath, handle); err != nil {
			return errors.Wrapf(err, "failed to check parent for %s", subPath)
		}

		srcPath, err := safeJoin(d.upperdir, subPath)
		if err != nil {
			return errors.Wrapf(err, "failed to join %s and %s", d.upperdir, subPath)
		}

		c := &change{
			kind:    kind,
			subPath: subPath,
			srcPath: srcPath,
		}

		if srcfi != nil {
			var ok bool
			c.srcStat, ok = srcfi.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.Errorf("unhandled stat type for %+v", srcfi)
			}

			if !srcfi.IsDir() && c.srcStat.Nlink > 1 {
				if linkSubPath, ok := d.inodes[statInode(c.srcStat)]; ok {
					c.linkSubPath = linkSubPath
				} else {
					d.inodes[statInode(c.srcStat)] = c.subPath
				}
			}
		}

		return handle(ctx, c)
	}, d.upperdir, d.upperRoot, d.lowerRoot)
}

func (d *differ) checkParent(ctx context.Context, subPath string, handle func(context.Context, *change) error) error {
	parentSubPath := filepath.Dir(subPath)
	if parentSubPath == "/" {
		return nil
	}
	if _, ok := d.visited[parentSubPath]; ok {
		return nil
	}
	d.visited[parentSubPath] = struct{}{}

	if err := d.checkParent(ctx, parentSubPath, handle); err != nil {
		return err
	}
	parentSrcPath, err := safeJoin(d.upperRoot, parentSubPath)
	if err != nil {
		return err
	}
	srcfi, err := os.Lstat(parentSrcPath)
	if err != nil {
		return err
	}
	parentSrcStat, ok := srcfi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.Errorf("unexpected type %T", srcfi)
	}
	return handle(ctx, &change{
		kind:    fs.ChangeKindModify,
		subPath: parentSubPath,
		srcPath: parentSrcPath,
		srcStat: parentSrcStat,
	})
}

func (d *differ) Release() error {
	var err error
	if d.releaseLower != nil {
		err = d.releaseLower()
		if err == nil {
			d.releaseLower = nil
		}
	}
	if d.releaseUpper != nil {
		err = multierror.Append(err, d.releaseUpper()).ErrorOrNil()
		if err == nil {
			d.releaseUpper = nil
		}
	}
	return err
}

func safeJoin(root, path string) (string, error) {
	dir, base := filepath.Split(path)
	parent, err := fs.RootPath(root, dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, base), nil
}

// needsUserXAttr checks whether overlay mounts should be provided the userxattr option. We can't use
// NeedsUserXAttr from the overlayutils package directly because we don't always have direct knowledge
// of the root of the snapshotter state (such as when using a remote snapshotter). Instead, we create
// a temporary new snapshot and test using its root, which works because single layer snapshots will
// use bind-mounts even when created by an overlay based snapshotter.
func needsUserXAttr(ctx context.Context, sn Snapshotter, lm leases.Manager) (bool, error) {
	key := identity.NewID()

	ctx, done, err := leaseutil.WithLease(ctx, lm, leaseutil.MakeTemporary)
	if err != nil {
		return false, errors.Wrap(err, "failed to create lease for checking user xattr")
	}
	defer done(context.TODO())

	err = sn.Prepare(ctx, key, "")
	if err != nil {
		return false, err
	}
	mntable, err := sn.Mounts(ctx, key)
	if err != nil {
		return false, err
	}
	mnts, unmount, err := mntable.Mount()
	if err != nil {
		return false, err
	}
	defer unmount()

	var userxattr bool
	if err := mount.WithTempMount(ctx, mnts, func(root string) error {
		var err error
		userxattr, err = overlayutils.NeedsUserXAttr(root)
		return err
	}); err != nil {
		return false, err
	}
	return userxattr, nil
}
