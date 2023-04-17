//go:build !windows
// +build !windows

package snapshot

import (
	"context"
	gofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/continuity/sysx"
	"github.com/hashicorp/go-multierror"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/overlay"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// opaqueWitheoutType is the type of whiteout to apply on an opaque directory
type opaqueWitheoutType int

const (
	// Use trusted.opaque xattr
	opaqueWitheoutTypeTrustedXattr opaqueWitheoutType = iota
	// Use user.opaque xattr
	opaqueWitheoutTypeUserXattr
	// Use fuse-overlayfs whiteout file
	opaqueWitheoutTypeFile
)

type changeApply struct {
	*change
	dstPath   string
	dstStat   *syscall.Stat_t
	setOpaque bool
}

type applier struct {
	root                 string
	release              func() error
	lowerdirs            []string // ordered highest -> lowest, the order we want to check them in
	crossSnapshotLinks   map[inode]struct{}
	createWhiteoutDelete bool
	whiteoutType         opaqueWitheoutType
	dirModTimes          map[string]unix.Timespec // map of dstPath -> mtime that should be set on that subPath
}

func applierFor(dest Mountable, tryCrossSnapshotLink bool, whiteoutType opaqueWitheoutType) (_ *applier, rerr error) {
	a := &applier{
		dirModTimes:  make(map[string]unix.Timespec),
		whiteoutType: whiteoutType,
	}
	defer func() {
		if rerr != nil {
			rerr = multierror.Append(rerr, a.Release()).ErrorOrNil()
		}
	}()
	if tryCrossSnapshotLink {
		a.crossSnapshotLinks = make(map[inode]struct{})
	}

	mnts, release, err := dest.Mount()
	if err != nil {
		return nil, nil
	}
	a.release = release

	if len(mnts) != 1 {
		return nil, errors.Errorf("expected exactly one mount, got %d", len(mnts))
	}
	mnt := mnts[0]

	if overlay.IsOverlayMountType(mnt) {
		for _, opt := range mnt.Options {
			if strings.HasPrefix(opt, "upperdir=") {
				a.root = strings.TrimPrefix(opt, "upperdir=")
			} else if strings.HasPrefix(opt, "lowerdir=") {
				a.lowerdirs = strings.Split(strings.TrimPrefix(opt, "lowerdir="), ":")
			}
		}
		if a.root == "" {
			return nil, errors.Errorf("could not find upperdir in mount options %v", mnt.Options)
		}
		if len(a.lowerdirs) == 0 {
			return nil, errors.Errorf("could not find lowerdir in mount options %v", mnt.Options)
		}
		a.createWhiteoutDelete = true
	} else if mnt.Type == "bind" || mnt.Type == "rbind" {
		a.root = mnt.Source
	} else {
		mnter := LocalMounter(dest)
		root, err := mnter.Mount()
		if err != nil {
			return nil, err
		}
		a.root = root
		prevRelease := a.release
		a.release = func() error {
			err := mnter.Unmount()
			return multierror.Append(err, prevRelease()).ErrorOrNil()
		}
	}

	a.root, err = filepath.EvalSymlinks(a.root)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve symlinks in %s", a.root)
	}
	return a, nil
}

func (a *applier) Apply(ctx context.Context, c *change) error {
	if c == nil {
		return errors.New("nil change")
	}

	if c.kind == fs.ChangeKindUnmodified {
		return nil
	}

	dstPath, err := safeJoin(a.root, c.subPath)
	if err != nil {
		return errors.Wrapf(err, "failed to join paths %q and %q", a.root, c.subPath)
	}
	var dstStat *syscall.Stat_t
	if dstfi, err := os.Lstat(dstPath); err == nil {
		stat, ok := dstfi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.Errorf("failed to get stat_t for %T", dstStat)
		}
		dstStat = stat
	} else if !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to stat during copy apply")
	}

	ca := &changeApply{
		change:  c,
		dstPath: dstPath,
		dstStat: dstStat,
	}

	if done, err := a.applyDelete(ctx, ca); err != nil {
		return errors.Wrap(err, "failed to delete during apply")
	} else if done {
		return nil
	}

	if done, err := a.applyHardlink(ctx, ca); err != nil {
		return errors.Wrapf(err, "failed to hardlink during apply")
	} else if done {
		return nil
	}

	if err := a.applyCopy(ctx, ca); err != nil {
		return errors.Wrapf(err, "failed to copy during apply")
	}
	return nil
}

func (a *applier) applyDelete(ctx context.Context, ca *changeApply) (bool, error) {
	// Even when not deleting, we may be overwriting a file, in which case we should
	// delete the existing file at the path, if any. Don't delete when both are dirs
	// in this case though because they should get merged, not overwritten.
	deleteOnly := ca.kind == fs.ChangeKindDelete
	overwrite := false

	if !deleteOnly {
		var err error
		if overwrite, err = a.checkOverwrite(ca); err != nil {
			return false, err
		}
	}

	if !deleteOnly && !overwrite {
		// nothing to delete, continue on
		return false, nil
	}

	if err := os.RemoveAll(ca.dstPath); err != nil {
		return false, errors.Wrap(err, "failed to remove during apply")
	}
	ca.dstStat = nil

	if overwrite && a.createWhiteoutDelete && ca.srcStat.Mode&unix.S_IFMT == unix.S_IFDIR {
		// If we are using an overlay snapshotter and overwriting an existing non-directory
		// with a directory, we need this new dir to be opaque so that any files from lowerdirs
		// under it are not visible.
		ca.setOpaque = true
	}

	if deleteOnly && a.createWhiteoutDelete {
		// only create a whiteout device if there is something to delete
		var foundLower bool
		for _, lowerdir := range a.lowerdirs {
			lowerPath, err := safeJoin(lowerdir, ca.subPath)
			if err != nil {
				return false, errors.Wrapf(err, "failed to join lowerdir %q and subPath %q", lowerdir, ca.subPath)
			}
			if _, err := os.Lstat(lowerPath); err == nil {
				foundLower = true
				break
			} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) {
				return false, errors.Wrapf(err, "failed to stat lowerPath %q", lowerPath)
			}
		}
		if foundLower {
			return a.createWhiteoutFile(ca)
		}
	}

	return deleteOnly, nil
}

func (a *applier) checkOverwrite(ca *changeApply) (overwrite bool, err error) {
	// We are overwritting:
	// - If destination exists and source and destination are not both directories
	if ca.dstStat != nil && ca.srcStat.Mode&ca.dstStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return true, nil
	}
	// - If they are both directories and the destination directory was deleted with a whiteout file
	if a.createWhiteoutDelete {
		dirpath := filepath.Dir(ca.dstPath)
		fileName := filepath.Base(ca.dstPath)
		withoutFilePath := filepath.Join(dirpath, overlay.OpaqueWitheoutFilePrefix+fileName)

		if _, err := os.Lstat(withoutFilePath); err == nil {
			// Remove the old whiteout file as we are replacing dstPath
			if err := os.Remove(withoutFilePath); err != nil {
				return false, errors.Wrap(err, "failed to remove whiteout during apply")
			}
			// Return overwrite: true to indicate we are overwriting a deleted file/directory
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, errors.Wrapf(err, "failed to lstat whiteout")
		}
	}

	return false, nil
}

func (a *applier) createWhiteoutFile(ca *changeApply) (bool, error) {
	ca.kind = fs.ChangeKindAdd

	// No need to check if ca.srcStat is == nil
	// This is always the case to properly handle the whiteout file creation

	if a.whiteoutType == opaqueWitheoutTypeFile {
		// Create a whiteout file instead of using a char 0/0 file
		dirpath := filepath.Dir(ca.dstPath)
		fileName := filepath.Base(ca.dstPath)

		withoutFileName := overlay.OpaqueWitheoutFilePrefix + fileName
		emptyFile, err := os.Create(filepath.Join(dirpath, withoutFileName))
		if err != nil {
			return false, errors.Wrapf(err, "failed to create whiteout for deleted file %s", ca.dstPath)
		}
		emptyFile.Close()

		// The whiteout file is created, mark the file as processed
		return true, nil
	} else {
		ca.srcStat = &syscall.Stat_t{
			Mode: syscall.S_IFCHR,
			Rdev: unix.Mkdev(0, 0),
		}
		ca.srcPath = ""
	}

	return false, nil
}

func (a *applier) applyHardlink(ctx context.Context, ca *changeApply) (bool, error) {
	switch ca.srcStat.Mode & unix.S_IFMT {
	case unix.S_IFDIR, unix.S_IFIFO, unix.S_IFSOCK:
		// Directories can't be hard-linked, so they just have to be recreated.
		// Named pipes and sockets can be hard-linked but is best to avoid as it could enable IPC in weird cases.
		return false, nil

	default:
		var linkSrcPath string
		if ca.linkSubPath != "" {
			// there's an already applied path that we should link from
			path, err := safeJoin(a.root, ca.linkSubPath)
			if err != nil {
				return false, errors.Errorf("failed to get hardlink source path: %v", err)
			}
			linkSrcPath = path
		} else if a.crossSnapshotLinks != nil {
			// we can try to link across snapshots from the source file
			linkSrcPath = ca.srcPath
			a.crossSnapshotLinks[statInode(ca.srcStat)] = struct{}{}
		}
		if linkSrcPath == "" {
			// nothing to hardlink from, will have to copy the file
			return false, nil
		}

		if err := os.Link(linkSrcPath, ca.dstPath); errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EMLINK) {
			// These errors are expected when the hardlink would cross devices or would exceed the maximum number of links for the inode.
			// Just fallback to a copy.
			bklog.G(ctx).WithError(err).WithField("srcPath", linkSrcPath).WithField("dstPath", ca.dstPath).Debug("hardlink failed")
			if a.crossSnapshotLinks != nil {
				delete(a.crossSnapshotLinks, statInode(ca.srcStat))
			}
			return false, nil
		} else if err != nil {
			return false, errors.Wrap(err, "failed to hardlink during apply")
		}

		return true, nil
	}
}

func (a *applier) applyCopy(ctx context.Context, ca *changeApply) error {
	switch ca.srcStat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if err := fs.CopyFile(ca.dstPath, ca.srcPath); err != nil {
			return errors.Wrapf(err, "failed to copy from %s to %s during apply", ca.srcPath, ca.dstPath)
		}
	case unix.S_IFDIR:
		if ca.dstStat == nil {
			// dstPath doesn't exist, make it a dir
			if err := unix.Mkdir(ca.dstPath, ca.srcStat.Mode); err != nil {
				return errors.Wrapf(err, "failed to create applied dir at %q from %q", ca.dstPath, ca.srcPath)
			}
		}
	case unix.S_IFLNK:
		if target, err := os.Readlink(ca.srcPath); err != nil {
			return errors.Wrap(err, "failed to read symlink during apply")
		} else if err := os.Symlink(target, ca.dstPath); err != nil {
			return errors.Wrap(err, "failed to create symlink during apply")
		}
	case unix.S_IFBLK, unix.S_IFCHR, unix.S_IFIFO, unix.S_IFSOCK:
		if err := unix.Mknod(ca.dstPath, ca.srcStat.Mode, int(ca.srcStat.Rdev)); err != nil {
			return errors.Wrap(err, "failed to mknod during apply")
		}
	default:
		// should never be here, all types should be handled
		return errors.Errorf("unhandled file type %d during merge at path %q", ca.srcStat.Mode&unix.S_IFMT, ca.srcPath)
	}

	// NOTE: it's important that chown happens before setting xattrs due to the fact that chown will
	// reset the security.capabilities xattr which results in file capabilities being lost.
	if err := os.Lchown(ca.dstPath, int(ca.srcStat.Uid), int(ca.srcStat.Gid)); err != nil {
		return errors.Wrap(err, "failed to chown during apply")
	}

	if ca.srcStat.Mode&unix.S_IFMT != unix.S_IFLNK {
		if err := unix.Chmod(ca.dstPath, ca.srcStat.Mode); err != nil {
			return errors.Wrapf(err, "failed to chmod path %q during apply", ca.dstPath)
		}
	}

	if ca.srcPath != "" {
		xattrs, err := sysx.LListxattr(ca.srcPath)
		if err != nil {
			return errors.Wrapf(err, "failed to list xattrs of src path %s", ca.srcPath)
		}
		for _, xattr := range xattrs {
			if isOpaqueXattr(xattr) {
				// Don't recreate opaque xattrs during merge based on the source file. The differs take care of converting
				// source path from the "opaque whiteout" format to the "explicit whiteout" format. The only time we set
				// opaque xattrs is handled after this loop below.
				continue
			}
			xattrVal, err := sysx.LGetxattr(ca.srcPath, xattr)
			if err != nil {
				return errors.Wrapf(err, "failed to get xattr %s of src path %s", xattr, ca.srcPath)
			}
			if err := sysx.LSetxattr(ca.dstPath, xattr, xattrVal, 0); err != nil {
				// This can often fail, so just log it: https://github.com/moby/buildkit/issues/1189
				bklog.G(ctx).Debugf("failed to set xattr %s of path %s during apply", xattr, ca.dstPath)
			}
		}
	}

	if ca.setOpaque {
		// This is set in the case where we are creating a directory that is replacing a whiteout device
		if err := setDirectoryOpaque(a.whiteoutType, ca.dstPath); err != nil {
			return err
		}
	}

	atimeSpec := unix.Timespec{Sec: ca.srcStat.Atim.Sec, Nsec: ca.srcStat.Atim.Nsec}
	mtimeSpec := unix.Timespec{Sec: ca.srcStat.Mtim.Sec, Nsec: ca.srcStat.Mtim.Nsec}
	if ca.srcStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		// apply times immediately for non-dirs
		if err := unix.UtimesNanoAt(unix.AT_FDCWD, ca.dstPath, []unix.Timespec{atimeSpec, mtimeSpec}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	} else {
		// save the times we should set on this dir, to be applied after subfiles have been set
		a.dirModTimes[ca.dstPath] = mtimeSpec
	}

	return nil
}

const (
	trustedOpaqueXattr = "trusted.overlay.opaque"
	userOpaqueXattr    = "user.overlay.opaque"
	fuseOpaqueXattr    = "user.fuseoverlayfs.opaque"
)

func isOpaqueXattr(s string) bool {
	for _, k := range []string{trustedOpaqueXattr, userOpaqueXattr, fuseOpaqueXattr} {
		if s == k {
			return true
		}
	}
	return false
}

func setDirectoryOpaque(witheoutType opaqueWitheoutType, dstPath string) error {
	if witheoutType == opaqueWitheoutTypeFile {
		emptyFile, err := os.Create(filepath.Join(dstPath, overlay.OpaqueWitheoutFileName))
		if err != nil {
			return errors.Wrapf(err, "failed to create opaque whiteout file %q in path %s", overlay.OpaqueWitheoutFileName, dstPath)
		}
		emptyFile.Close()
	} else {
		xattr := trustedOpaqueXattr

		if witheoutType == opaqueWitheoutTypeUserXattr {
			xattr = userOpaqueXattr
		}

		if err := sysx.LSetxattr(dstPath, xattr, []byte{'y'}, 0); err != nil {
			return errors.Wrapf(err, "failed to set opaque xattr %q of path %s", xattr, dstPath)
		}
	}

	return nil
}

func (a *applier) Flush() error {
	// Set dir times now that everything has been modified. Walk the filesystem tree to ensure
	// that we never try to apply to a path that has been deleted or modified since times for it
	// were stored. This is needed for corner cases such as where a parent dir is removed and
	// replaced with a symlink.
	return filepath.WalkDir(a.root, func(path string, d gofs.DirEntry, prevErr error) error {
		if prevErr != nil {
			return prevErr
		}
		if !d.IsDir() {
			return nil
		}
		if mtime, ok := a.dirModTimes[path]; ok {
			if err := unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{{Nsec: unix.UTIME_OMIT}, mtime}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
		}
		return nil
	})
}

func (a *applier) Release() error {
	if a.release != nil {
		err := a.release()
		if err != nil {
			return err
		}
	}
	a.release = nil
	return nil
}

func (a *applier) Usage() (snapshots.Usage, error) {
	// Calculate the disk space used under the apply root, similar to the normal containerd snapshotter disk usage
	// calculations but with the extra ability to take into account hardlinks that were created between snapshots, ensuring that
	// they don't get double counted.
	inodes := make(map[inode]struct{})
	var usage snapshots.Usage
	if err := filepath.WalkDir(a.root, func(path string, dirent gofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := dirent.Info()
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		inode := statInode(stat)
		if _, ok := inodes[inode]; ok {
			return nil
		}
		inodes[inode] = struct{}{}
		if a.crossSnapshotLinks != nil {
			if _, ok := a.crossSnapshotLinks[statInode(stat)]; ok {
				// don't count cross-snapshot hardlinks
				return nil
			}
		}
		usage.Inodes++
		usage.Size += stat.Blocks * 512 // 512 is always block size, see "man 2 stat"
		return nil
	}); err != nil {
		return snapshots.Usage{}, err
	}
	return usage, nil
}
