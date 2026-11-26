// Copyright 2020 The gVisor Authors.
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

package overlay

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

func isWhiteout(stat *linux.Statx) bool {
	return stat.Mode&linux.S_IFMT == linux.S_IFCHR && stat.RdevMajor == 0 && stat.RdevMinor == 0
}

// DrainDentryCache implements vfs.FilesystemImpl.DrainDentryCache.
func (fs *filesystem) DrainDentryCache(ctx context.Context) error {
	return linuxerr.EOPNOTSUPP
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	if fs.opts.UpperRoot.Ok() {
		return fs.opts.UpperRoot.Mount().Filesystem().Impl().Sync(ctx)
	}
	return nil
}

var dentrySlicePool = sync.Pool{
	New: func() any {
		ds := make([]*dentry, 0, 4) // arbitrary non-zero initial capacity
		return &ds
	},
}

func appendDentry(ds *[]*dentry, d *dentry) *[]*dentry {
	if ds == nil {
		ds = dentrySlicePool.Get().(*[]*dentry)
	}
	*ds = append(*ds, d)
	return ds
}

// Preconditions: ds != nil.
func putDentrySlice(ds *[]*dentry) {
	// Allow dentries to be GC'd.
	for i := range *ds {
		(*ds)[i] = nil
	}
	*ds = (*ds)[:0]
	dentrySlicePool.Put(ds)
}

// renameMuRUnlockAndCheckDrop calls fs.renameMu.RUnlock(), then calls
// dentry.checkDropLocked on all dentries in *dsp with fs.renameMu locked for
// writing.
//
// dsp is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentry slices are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndCheckDrop(&ds)" than "defer func() {
// fs.renameMuRUnlockAndCheckDrop(ds) }()" to work around this.
//
// +checklocksreleaseread:fs.renameMu
func (fs *filesystem) renameMuRUnlockAndCheckDrop(ctx context.Context, dsp **[]*dentry) {
	idx := fs.renameLockIndex()
	fs.renameMu.NestedRUnlock(idx)
	if *dsp == nil {
		return
	}
	ds := **dsp
	// Only go through calling dentry.checkDropLocked() (which requires
	// re-locking renameMu) if we actually have any dentries with zero refs.
	checkAny := false
	for i := range ds {
		if ds[i].refs.Load() == 0 {
			checkAny = true
			break
		}
	}
	if checkAny {
		fs.renameMu.NestedLock(idx)
		for _, d := range ds {
			d.checkDropLocked(ctx)
		}
		fs.renameMu.NestedUnlock(idx)
	}
	putDentrySlice(*dsp)
}

// +checklocksrelease:fs.renameMu
func (fs *filesystem) renameMuUnlockAndCheckDrop(ctx context.Context, ds **[]*dentry) {
	idx := fs.renameLockIndex()
	if *ds == nil {
		fs.renameMu.NestedUnlock(idx)
		return
	}
	for _, d := range **ds {
		d.checkDropLocked(ctx)
	}
	fs.renameMu.NestedUnlock(idx)
	putDentrySlice(*ds)
}

// stepLocked resolves rp.Component() to an existing file, starting from the
// given directory.
//
// Dentries which may have a reference count of zero, and which therefore
// should be dropped once traversal is complete, are appended to ds.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - d.dirMu must be locked.
//   - !rp.Done().
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, lookupLayer, bool, error) {
	if !d.isDir() {
		return nil, lookupLayerNone, false, linuxerr.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, lookupLayerNone, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, d.topLookupLayer(), false, nil
	}
	if name == ".." {
		parent := d.parent.Load()
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, lookupLayerNone, false, err
		} else if isRoot || parent == nil {
			rp.Advance()
			return d, d.topLookupLayer(), false, nil
		}
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			return nil, lookupLayerNone, false, err
		}
		rp.Advance()
		return parent, parent.topLookupLayer(), false, nil
	}
	if uint64(len(name)) > fs.maxFilenameLen {
		return nil, lookupLayerNone, false, linuxerr.ENAMETOOLONG
	}
	child, topLookupLayer, err := fs.getChildLocked(ctx, d, name, ds)
	if err != nil {
		return nil, topLookupLayer, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, lookupLayerNone, false, err
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx)
		if err != nil {
			return nil, lookupLayerNone, false, err
		}
		followedSymlink, err := rp.HandleSymlink(target)
		return d, topLookupLayer, followedSymlink, err
	}
	rp.Advance()
	return child, topLookupLayer, false, nil
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - d.dirMu must be locked.
func (fs *filesystem) getChildLocked(ctx context.Context, parent *dentry, name string, ds **[]*dentry) (*dentry, lookupLayer, error) {
	if child, ok := parent.children[name]; ok {
		return child, child.topLookupLayer(), nil
	}
	child, topLookupLayer, err := fs.lookupLocked(ctx, parent, name)
	if err != nil {
		return nil, topLookupLayer, err
	}
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	parent.children[name] = child
	// child's refcount is initially 0, so it may be dropped after traversal.
	*ds = appendDentry(*ds, child)
	return child, topLookupLayer, nil
}

// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.dirMu must be locked.
func (fs *filesystem) lookupLocked(ctx context.Context, parent *dentry, name string) (*dentry, lookupLayer, error) {
	childPath := fspath.Parse(name)
	child := fs.newDentry()
	topLookupLayer := lookupLayerNone
	var lookupErr error

	vfsObj := fs.vfsfs.VirtualFilesystem()
	parent.iterLayers(func(parentVD vfs.VirtualDentry, isUpper bool) bool {
		if isUpper && fs.isTempName(name) {
			// Temporary files on the upper layer are not visible.
			return true
		}
		childVD, err := vfsObj.GetDentryAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  parentVD,
			Start: parentVD,
			Path:  childPath,
		}, &vfs.GetDentryOptions{})
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
			// The file doesn't exist on this layer. Proceed to the next one.
			return true
		}
		if err != nil {
			lookupErr = err
			return false
		}
		defer childVD.DecRef(ctx)

		mask := uint32(linux.STATX_TYPE)
		if topLookupLayer == lookupLayerNone {
			// Mode, UID, GID, and (for non-directories) inode number come from
			// the topmost layer on which the file exists.
			mask |= linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID | linux.STATX_INO
		}
		childPop := &vfs.PathOperation{
			Root:  childVD,
			Start: childVD,
		}
		stat, err := vfsObj.StatAt(ctx, fs.creds, childPop, &vfs.StatOptions{
			Mask: mask,
		})
		if err != nil {
			lookupErr = err
			return false
		}
		if stat.Mask&mask != mask {
			lookupErr = linuxerr.EREMOTE
			return false
		}

		if isWhiteout(&stat) {
			// This is a whiteout, so it "doesn't exist" on this layer, and
			// layers below this one are ignored.
			if isUpper {
				topLookupLayer = lookupLayerUpperWhiteout
			}
			return false
		}
		isDir := stat.Mode&linux.S_IFMT == linux.S_IFDIR
		if topLookupLayer != lookupLayerNone && !isDir {
			// Directories are not merged with non-directory files from lower
			// layers; instead, layers including and below the first
			// non-directory file are ignored. (This file must be a directory
			// on previous layers, since lower layers aren't searched for
			// non-directory files.)
			return false
		}

		// Update child to include this layer.
		childVD.IncRef()
		if isUpper {
			child.upperVD = childVD
			child.copiedUp = atomicbitops.FromUint32(1)
		} else {
			child.lowerVDs = append(child.lowerVDs, childVD)
		}
		if topLookupLayer == lookupLayerNone {
			if isUpper {
				topLookupLayer = lookupLayerUpper
			} else {
				topLookupLayer = lookupLayerLower
			}

			// Fetch POSIX ACLs.
			acl, err := vfsObj.GetPosixACLAt(ctx, fs.creds, childPop, vfs.AccessACL)
			if err != nil {
				lookupErr = err
				return false
			}
			defaultACL, err := vfsObj.GetPosixACLAt(ctx, fs.creds, childPop, vfs.DefaultACL)
			if err != nil {
				lookupErr = err
				return false
			}

			child.mode = atomicbitops.FromUint32(uint32(stat.Mode))
			child.accessACL.Store(acl)
			child.defaultACL.Store(defaultACL)
			child.uid = atomicbitops.FromUint32(stat.UID)
			child.gid = atomicbitops.FromUint32(stat.GID)
			child.devMajor = atomicbitops.FromUint32(stat.DevMajor)
			child.devMinor = atomicbitops.FromUint32(stat.DevMinor)
			child.ino = atomicbitops.FromUint64(stat.Ino)
		}

		// For non-directory files, only the topmost layer that contains a file
		// matters.
		if !isDir {
			return false
		}

		// Directories use the lowest layer inode and device numbers to generate a
		// filesystem local inode number. This way the inode number does not change
		// after copy ups.
		child.devMajor = atomicbitops.FromUint32(stat.DevMajor)
		child.devMinor = atomicbitops.FromUint32(stat.DevMinor)
		child.ino = atomicbitops.FromUint64(stat.Ino)

		// Directories are merged with directories from lower layers if they
		// are not explicitly opaque.
		opaqueVal, err := vfsObj.GetXattrAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  childVD,
			Start: childVD,
		}, &vfs.GetXattrOptions{
			Name: fs.xattrOpaque,
			Size: 1,
		})
		return !(err == nil && opaqueVal == "y")
	})

	if lookupErr != nil {
		child.destroyLocked(ctx)
		return nil, topLookupLayer, lookupErr
	}
	if !topLookupLayer.existsInOverlay() {
		child.destroyLocked(ctx)
		return nil, topLookupLayer, linuxerr.ENOENT
	}

	// Device and inode numbers were copied from the topmost layer above for
	// non-directories. They were copied from the bottommost layer for
	// directories. Override them if necessary. We can use RacyLoad() because
	// child is still being initialized.
	if child.isDir() {
		orig := layerDevNoAndIno{
			layerDevNumber: layerDevNumber{child.devMajor.RacyLoad(), child.devMinor.RacyLoad()},
			ino:            child.ino.RacyLoad(),
		}
		child.ino.Store(fs.newDirIno(orig))
		child.dirInoHash = orig
		child.devMajor = atomicbitops.FromUint32(linux.UNNAMED_MAJOR)
		child.devMinor = atomicbitops.FromUint32(fs.dirDevMinor)
	} else if !child.upperVD.Ok() {
		childDevMinor, err := fs.getLowerDevMinor(child.devMajor.RacyLoad(), child.devMinor.RacyLoad())
		if err != nil {
			ctx.Infof("overlay.filesystem.lookupLocked: failed to map lower layer device number (%d, %d) to an overlay-specific device number: %v", child.devMajor.RacyLoad(), child.devMinor.RacyLoad(), err)
			child.destroyLocked(ctx)
			return nil, topLookupLayer, err
		}
		child.devMajor = atomicbitops.FromUint32(linux.UNNAMED_MAJOR)
		child.devMinor = atomicbitops.FromUint32(childDevMinor)
	}

	parent.IncRef()
	child.parent.Store(parent)
	child.name = name
	return child, topLookupLayer, nil
}

// lookupLayerLocked is similar to lookupLocked, but only returns information
// about the file rather than a dentry.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.dirMu must be locked.
func (fs *filesystem) lookupLayerLocked(ctx context.Context, parent *dentry, name string) (lookupLayer, error) {
	childPath := fspath.Parse(name)
	lookupLayer := lookupLayerNone
	var lookupErr error

	parent.iterLayers(func(parentVD vfs.VirtualDentry, isUpper bool) bool {
		if isUpper && fs.isTempName(name) {
			// Temporary files on the upper layer are not visible.
			return true
		}
		stat, err := fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  parentVD,
			Start: parentVD,
			Path:  childPath,
		}, &vfs.StatOptions{
			Mask: linux.STATX_TYPE,
		})
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
			// The file doesn't exist on this layer. Proceed to the next
			// one.
			return true
		}
		if err != nil {
			lookupErr = err
			return false
		}
		if stat.Mask&linux.STATX_TYPE == 0 {
			// Linux's overlayfs tends to return EREMOTE in cases where a file
			// is unusable for reasons that are not better captured by another
			// errno.
			lookupErr = linuxerr.EREMOTE
			return false
		}
		if isWhiteout(&stat) {
			// This is a whiteout, so it "doesn't exist" on this layer, and
			// layers below this one are ignored.
			if isUpper {
				lookupLayer = lookupLayerUpperWhiteout
			}
			return false
		}
		// The file exists; we can stop searching.
		if isUpper {
			lookupLayer = lookupLayerUpper
		} else {
			lookupLayer = lookupLayerLower
		}
		return false
	})

	return lookupLayer, lookupErr
}

type lookupLayer int

const (
	// lookupLayerNone indicates that no file exists at the given path on the
	// upper layer, and is either whited out or does not exist on lower layers.
	// Therefore, the file does not exist in the overlay filesystem, and file
	// creation may proceed normally (if an upper layer exists).
	lookupLayerNone lookupLayer = iota

	// lookupLayerLower indicates that no file exists at the given path on the
	// upper layer, but exists on a lower layer. Therefore, the file exists in
	// the overlay filesystem, but must be copied-up before mutation.
	lookupLayerLower

	// lookupLayerUpper indicates that a non-whiteout file exists at the given
	// path on the upper layer. Therefore, the file exists in the overlay
	// filesystem, and is already copied-up.
	lookupLayerUpper

	// lookupLayerUpperWhiteout indicates that a whiteout exists at the given
	// path on the upper layer. Therefore, the file does not exist in the
	// overlay filesystem, and file creation must replace the whiteout.
	lookupLayerUpperWhiteout
)

func (ll lookupLayer) existsInOverlay() bool {
	return ll == lookupLayerLower || ll == lookupLayerUpper
}

// walkParentDirLocked resolves all but the last path component of rp to an
// existing directory, starting from the given directory (which is usually
// rp.Start().Impl().(*dentry)). It does not check that the returned directory
// is searchable by the provider of rp.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, ds **[]*dentry) (*dentry, error) {
	dirIdx := d.dirLockIndex(dirLockD1)
	for !rp.Final() {
		d.dirMu.NestedLock(dirIdx)
		next, _, _, err := fs.stepLocked(ctx, rp, d, ds)
		d.dirMu.NestedUnlock(dirIdx)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.renameMu must be locked.
func (fs *filesystem) resolveLocked(ctx context.Context, rp *vfs.ResolvingPath, ds **[]*dentry) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	dirIdx := d.dirLockIndex(dirLockD1)
	for !rp.Done() {
		d.dirMu.NestedLock(dirIdx)
		next, _, _, err := fs.stepLocked(ctx, rp, d, ds)
		d.dirMu.NestedUnlock(dirIdx)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

type createType int

const (
	createNonDirectory createType = iota
	createDirectory
	createSyntheticMountpoint
)

// doCreateAt checks that creating a file at rp is permitted, then invokes
// create to do so.
//
// Preconditions:
//   - !rp.Done().
//   - For the final path component in rp, !rp.ShouldFollowSymlink().
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, ct createType, create func(parent *dentry, name string, haveUpperWhiteout bool, ds **[]*dentry) error) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	if uint64(len(name)) > fs.maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	if fs.isTempName(name) {
		// The upper layer has a file with this name, which is not visible.
		return linuxerr.EINVAL
	}
	if parent.vfsd.IsDead() {
		return linuxerr.ENOENT
	}

	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}

	dirIdx := parent.dirLockIndex(dirLockD1)
	parent.dirMu.NestedLock(dirIdx)
	defer parent.dirMu.NestedUnlock(dirIdx)

	// Determine if a file already exists at name.
	if _, ok := parent.children[name]; ok {
		return linuxerr.EEXIST
	}
	childLayer, err := fs.lookupLayerLocked(ctx, parent, name)
	if err != nil {
		return err
	}
	if childLayer.existsInOverlay() {
		return linuxerr.EEXIST
	}

	if ct == createNonDirectory && rp.MustBeDir() {
		return linuxerr.ENOENT
	}

	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	// Ensure that the parent directory is copied-up so that we can create the
	// new file in the upper layer.
	if err := parent.copyUpMaybeSyntheticMountpointLocked(ctx, ct == createSyntheticMountpoint, false /* skipData */, false /* mayUnlockRenameMu */); err != nil {
		return err
	}

	// Finally create the new file.
	if err := create(parent, name, childLayer == lookupLayerUpperWhiteout, &ds); err != nil {
		return err
	}

	parent.dirents = nil
	ev := linux.IN_CREATE
	if ct != createNonDirectory {
		ev |= linux.IN_ISDIR
	}
	parent.watches.Notify(withDropList(ctx, &ds), name, uint32(ev), 0 /* cookie */, vfs.InodeEvent, false /* unlinked */)
	return nil
}

// CreateWhiteout creates a whiteout at pop. Whiteouts are created with
// character devices with device ID = 0.
//
// Preconditions: pop's parent directory has been copied up.
func CreateWhiteout(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, pop *vfs.PathOperation) error {
	major, minor := linux.DecodeDeviceID(linux.WHITEOUT_DEV)
	return vfsObj.MknodAt(ctx, creds, pop, &vfs.MknodOptions{
		Mode:     linux.S_IFCHR | linux.WHITEOUT_MODE,
		DevMajor: uint32(major),
		DevMinor: minor,
	})
}

// createUpperLocked calls create to make a file at name in parent on the
// upper layer. If haveUpperWhiteout is true, there is a whiteout at name on the
// upper layer, which the new file replaces. isDir is true if create makes a
// directory.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.dirMu must be locked.
//   - parent has been copied up.
func (fs *filesystem) createUpperLocked(ctx context.Context, parent *dentry, name string, haveUpperWhiteout, isDir bool, create func(pop vfs.PathOperation) error) error {
	if haveUpperWhiteout {
		return fs.createOverWhiteout(ctx, parent.upperVD, name, isDir, create)
	}
	return create(layerChildPop(parent.upperVD, name))
}

// AccessAt implements vfs.Filesystem.Impl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return err
	}
	if err := d.checkPermissions(creds, ats); err != nil {
		return err
	}
	if err := vfs.CheckMountAccess(rp, ats, linux.FileMode(d.mode.Load())); err != nil {
		return err
	}
	if !ats.MayWrite() {
		// Not requesting write permission.  Allow it.
		return nil
	}
	// copyMu may not be held, so read the atomic copied-up flag rather than upperVD.
	if !d.isCopiedUp() && !d.canBeCopiedUp() {
		// A lower layer file that can not be copied up, can not be written to.
		// Error out here. Don't give the application false hopes.
		return linuxerr.EACCES
	}
	return nil
}

// BoundEndpointAt implements vfs.FilesystemImpl.BoundEndpointAt.
func (fs *filesystem) BoundEndpointAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.BoundEndpointOptions) (transport.BoundEndpoint, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, err
	}
	layerVD := d.topLayer()
	return fs.vfsfs.VirtualFilesystem().BoundEndpointAt(ctx, fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	}, &opts)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	d, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, createNonDirectory, func(parent *dentry, childName string, haveUpperWhiteout bool, ds **[]*dentry) error {
		if rp.Mount() != vd.Mount() {
			return linuxerr.EXDEV
		}
		old := vd.Dentry().Impl().(*dentry)
		if old.isDir() {
			return linuxerr.EPERM
		}
		if err := old.copyUpLocked(ctx); err != nil {
			return err
		}
		vfsObj := fs.vfsfs.VirtualFilesystem()
		createCreds := parent.credsForCreate(rp.Credentials(), parent.isSGIDSet())
		create := func(pop vfs.PathOperation) error {
			return vfsObj.LinkAt(ctx, createCreds, &vfs.PathOperation{
				Root:  old.upperVD,
				Start: old.upperVD,
			}, &pop)
		}
		if err := fs.createUpperLocked(ctx, parent, childName, haveUpperWhiteout, false /* isDir */, create); err != nil {
			return err
		}
		old.watches.Notify(withDropList(ctx, ds), "", linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent, false /* unlinked */)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	ct := createDirectory
	if opts.ForSyntheticMountpoint {
		ct = createSyntheticMountpoint
	}
	return fs.doCreateAt(ctx, rp, ct, func(parent *dentry, childName string, haveUpperWhiteout bool, ds **[]*dentry) error {
		vfsObj := fs.vfsfs.VirtualFilesystem()
		sgidSet := parent.isSGIDSet()
		if sgidSet {
			// Directories inherit the SGID bit.
			opts.Mode |= linux.ModeSetGID
		}
		createCreds := parent.credsForCreate(rp.Credentials(), sgidSet)
		create := func(pop vfs.PathOperation) error {
			return vfsObj.MkdirAt(ctx, createCreds, &pop, &opts)
		}
		if err := fs.createUpperLocked(ctx, parent, childName, haveUpperWhiteout, true /* isDir */, create); err != nil {
			return err
		}
		if !haveUpperWhiteout && len(parent.lowerVDs) > 0 {
			// If haveUpperWhiteout is false and the parent is merged, then we should
			// apply an optimization. We know that nothing exists on the parent's
			// lower layers. Otherwise doCreateAt() would have failed with EEXIST.
			// Mark the new directory opaque to avoid unnecessary lower lookups in
			// fs.lookupLocked(). Allow it to fail since this is an optimization.
			// See fs/overlayfs/dir.c:ovl_create_upper() -> ovl_set_opaque().
			pop := layerChildPop(parent.upperVD, childName)
			_ = fs.setOpaque(ctx, &pop)
		}
		return nil
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, createNonDirectory, func(parent *dentry, childName string, haveUpperWhiteout bool, ds **[]*dentry) error {
		// Disallow attempts to create whiteouts.
		if opts.Mode&linux.S_IFMT == linux.S_IFCHR && opts.DevMajor == 0 && opts.DevMinor == 0 {
			return linuxerr.EPERM
		}
		vfsObj := fs.vfsfs.VirtualFilesystem()
		createCreds := parent.credsForCreate(rp.Credentials(), parent.isSGIDSet())
		create := func(pop vfs.PathOperation) error {
			return vfsObj.MknodAt(ctx, createCreds, &pop, &opts)
		}
		return fs.createUpperLocked(ctx, parent, childName, haveUpperWhiteout, false /* isDir */, create)
	})
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	mayCreate := opts.Flags&linux.O_CREAT != 0
	mustCreate := opts.Flags&(linux.O_CREAT|linux.O_EXCL) == (linux.O_CREAT | linux.O_EXCL)

	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
			unlocked = true
		}
	}
	defer unlock()

	start := rp.Start().Impl().(*dentry)
	if rp.Done() {
		if mayCreate && rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		// The start is a file if the path ends at the root of a file bind
		// mount or at a magic link to a file.
		if rp.MustBeDir() && !start.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		// ensureOpenableLocked may release renameMu, so pin the dentry first.
		start.IncRef()
		err := start.ensureOpenableLocked(ctx, rp, &opts)
		unlock()
		defer start.DecRef(ctx)
		if err != nil {
			return nil, err
		}
		return start.openCopiedUp(ctx, rp, &opts)
	}

afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return nil, err
	}
	// Check for search permission in the parent directory.
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	// Reject attempts to open directories with O_CREAT.
	if mayCreate && rp.MustBeDir() {
		return nil, linuxerr.EISDIR
	}
	// Determine whether or not we need to create a file.
	dirIdx := parent.dirLockIndex(dirLockD1)
	parent.dirMu.NestedLock(dirIdx)
	child, topLookupLayer, followedSymlink, err := fs.stepLocked(ctx, rp, parent, &ds)
	if followedSymlink {
		parent.dirMu.NestedUnlock(dirIdx)
		if mustCreate {
			// EEXIST must be returned if an existing symlink is opened with O_EXCL.
			return nil, linuxerr.EEXIST
		}
		if err != nil {
			// If followedSymlink && err != nil, then this symlink resolution error
			// must be handled by the VFS layer.
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	if linuxerr.Equals(linuxerr.ENOENT, err) && mayCreate {
		fd, err := fs.createAndOpenLocked(ctx, rp, parent, &opts, &ds, topLookupLayer == lookupLayerUpperWhiteout)
		parent.dirMu.NestedUnlock(dirIdx)
		return fd, err
	}
	parent.dirMu.NestedUnlock(dirIdx)
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	if rp.MustBeDir() && !child.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	// ensureOpenableLocked may release renameMu, so pin the dentry first.
	child.IncRef()
	err = child.ensureOpenableLocked(ctx, rp, &opts)
	unlock()
	defer child.DecRef(ctx)
	if err != nil {
		return nil, err
	}
	return child.openCopiedUp(ctx, rp, &opts)
}

// ensureOpenableLocked may temporarily release filesystem.renameMu while
// copying d's data up; see copyUpForWriteLocked.
//
// Preconditions: filesystem.renameMu must be locked for reading, and the
// caller must hold a reference on d.
func (d *dentry) ensureOpenableLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) error {
	ats := vfs.AccessTypesForOpenFlags(opts)
	if err := d.checkPermissions(rp.Credentials(), ats); err != nil {
		return err
	}
	if d.isDir() {
		if ats.MayWrite() {
			return linuxerr.EISDIR
		}
		if opts.Flags&linux.O_CREAT != 0 {
			return linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return linuxerr.EINVAL
		}
		return nil
	}

	if !ats.MayWrite() {
		return nil
	}
	// Reject writes to a file that is currently being executed, as Linux does
	// in fs/namei.c:may_open() and fs/open.c:handle_truncate(). This must
	// happen before copy-up, since copying up would otherwise create a fresh
	// upper file with a zero write count and silently bypass the check.
	if err := d.writeCount.CheckWrite(); err != nil {
		return err
	}
	// copyMu may not be held, so read the atomic copied-up flag rather than upperVD.
	if !d.isCopiedUp() && !d.canBeCopiedUp() {
		return linuxerr.EPERM
	}
	if linux.FileMode(d.mode.Load()).IsSpecialFile() {
		return nil
	}

	// Copy up!
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	if opts.Flags&linux.O_TRUNC != 0 {
		return d.copyUpForTruncateLocked(ctx)
	}
	return d.copyUpForWriteLocked(ctx)
}

// Preconditions: If vfs.AccessTypesForOpenFlags(opts).MayWrite() and d is not a
// special file, then d has been copied up.
func (d *dentry) openCopiedUp(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	mnt := rp.Mount()

	// Directory FDs open FDs from each layer when directory entries are read,
	// so they don't require opening an FD from d.topLayer() up front.
	ftype := d.mode.Load() & linux.S_IFMT
	if ftype == linux.S_IFDIR {
		fd := &directoryFD{}
		fd.LockFD.Init(&d.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), mnt, &d.vfsd, &vfs.FileDescriptionOptions{
			UseDentryMetadata: true,
		}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	}

	layerVD, isUpper := d.topLayerInfo()
	layerFD, err := rp.VirtualFilesystem().OpenAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	}, opts)
	if err != nil {
		return nil, err
	}
	if ftype != linux.S_IFREG {
		return layerFD, nil
	}
	layerFlags := layerFD.StatusFlags()
	fd := &regularFileFD{
		copiedUp:    isUpper,
		cachedFD:    layerFD,
		cachedFlags: layerFlags,
	}
	fd.LockFD.Init(&d.locks)
	layerFDOpts := layerFD.Options()
	if err := fd.vfsfd.Init(fd, layerFlags, rp.Credentials(), mnt, &d.vfsd, &layerFDOpts); err != nil {
		layerFD.DecRef(ctx)
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Preconditions:
//   - parent.dirMu must be locked.
//   - parent does not already contain a child named rp.Component().
func (fs *filesystem) createAndOpenLocked(ctx context.Context, rp *vfs.ResolvingPath, parent *dentry, opts *vfs.OpenOptions, ds **[]*dentry, haveUpperWhiteout bool) (*vfs.FileDescription, error) {
	creds := rp.Credentials()
	if err := parent.checkPermissions(creds, vfs.MayWrite); err != nil {
		return nil, err
	}
	if parent.vfsd.IsDead() {
		return nil, linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	defer mnt.EndWrite()

	if err := parent.copyUpLocked(ctx); err != nil {
		return nil, err
	}

	vfsObj := fs.vfsfs.VirtualFilesystem()
	childName := rp.Component()
	if fs.isTempName(childName) {
		// The upper layer has a file with this name, which is not visible.
		return nil, linuxerr.EINVAL
	}
	// Create the file on the upper layer, and get an FD representing it.
	createCreds := parent.credsForCreate(creds, parent.isSGIDSet())
	var upperFD *vfs.FileDescription
	create := func(pop vfs.PathOperation) error {
		fd, err := vfsObj.OpenAt(ctx, createCreds, &pop, &vfs.OpenOptions{
			Flags: opts.Flags&^vfs.FileCreationFlags | linux.O_CREAT | linux.O_EXCL,
			Mode:  opts.Mode,
		})
		if err != nil {
			return err
		}
		upperFD = fd
		return nil
	}
	if err := fs.createUpperLocked(ctx, parent, childName, haveUpperWhiteout, false /* isDir */, create); err != nil {
		if upperFD != nil {
			upperFD.DecRef(ctx)
		}
		return nil, err
	}

	// Re-lookup to get a dentry representing the new file, which is needed for
	// the returned FD.
	child, _, err := fs.getChildLocked(ctx, parent, childName, ds)
	if err != nil {
		upperFD.DecRef(ctx)
		// Remove the new file, and restore the whiteout if there was one.
		if haveUpperWhiteout {
			if undoErr := fs.replaceWithWhiteout(ctx, parent.upperVD, childName); undoErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to replace new file with whiteout after OpenAt(O_CREAT) dentry lookup failure: %v", undoErr))
			}
		} else {
			pop := layerChildPop(parent.upperVD, childName)
			if undoErr := vfsObj.UnlinkAt(ctx, fs.creds, &pop); undoErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to delete upper layer file after OpenAt(O_CREAT) dentry lookup failure: %v", undoErr))
			}
		}
		parent.dirents = nil
		return nil, err
	}
	// Finally construct the overlay FD. Below this point, we don't perform
	// cleanup (the file was created successfully even if we can no longer open
	// it for some reason).
	parent.dirents = nil
	upperFlags := upperFD.StatusFlags()
	fd := &regularFileFD{
		copiedUp:    true,
		cachedFD:    upperFD,
		cachedFlags: upperFlags,
	}
	fd.LockFD.Init(&child.locks)
	upperFDOpts := upperFD.Options()
	if err := fd.vfsfd.Init(fd, upperFlags, rp.Credentials(), mnt, &child.vfsd, &upperFDOpts); err != nil {
		upperFD.DecRef(ctx)
		return nil, err
	}
	parent.watches.Notify(withDropList(ctx, ds), childName, linux.IN_CREATE, 0 /* cookie */, vfs.PathEvent, false /* unlinked */)
	fd.vfsfd.SetCreated()
	return &fd.vfsfd, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}
	layerVD := d.topLayer()
	return fs.vfsfs.VirtualFilesystem().ReadlinkAt(ctx, d.fs.creds, &vfs.PathOperation{
		Root:  layerVD,
		Start: layerVD,
	})
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	// Resolve newParent first to verify that it's on this Mount.
	var ds *[]*dentry
	fs.renameMu.NestedLock(fs.renameLockIndex())
	// We need to DecRef outside of fs.mu because forgetting a dead mountpoint
	// could result in this filesystem being released which acquires fs.mu.
	var toDecRef []refs.RefCounter
	var layerOp *vfs.LayerOperation
	defer func() {
		layerOp.Finish(ctx)
		for _, ref := range toDecRef {
			ref.DecRef(ctx)
		}
	}()
	defer fs.renameMuUnlockAndCheckDrop(ctx, &ds)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry), &ds)
	if err != nil {
		return err
	}

	if opts.Flags&^(linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE) != 0 {
		return linuxerr.EINVAL
	}
	if opts.Flags&(linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE) == linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE {
		return linuxerr.EINVAL
	}
	exchange := opts.Flags&linux.RENAME_EXCHANGE != 0

	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		return linuxerr.EBUSY
	}
	if uint64(len(newName)) > fs.maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	if fs.isTempName(newName) {
		// The upper layer has a file with this name, which is not visible.
		return linuxerr.EINVAL
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	creds := rp.Credentials()
	if err := oldParent.checkPermissions(creds, vfs.MayExec); err != nil {
		return err
	}
	// We need a dentry representing the renamed file since, if it's a
	// directory, we need to check for write permission on it.
	oldDirIdx := oldParent.dirLockIndex(dirLockD1)
	oldParent.dirMu.NestedLock(oldDirIdx)
	defer oldParent.dirMu.NestedUnlock(oldDirIdx)
	renamed, _, err := fs.getChildLocked(ctx, oldParent, oldName, &ds)
	if err != nil {
		return err
	}
	if oldParent != newParent {
		if err := newParent.checkPermissions(creds, vfs.MayExec); err != nil {
			return err
		}
		newDirIdx := newParent.dirLockIndex(dirLockD1New)
		newParent.dirMu.NestedLock(newDirIdx)
		defer newParent.dirMu.NestedUnlock(newDirIdx)
	}
	replaced, replacedLayer, replacedErr := fs.getChildLocked(ctx, newParent, newName, &ds)
	// A rename or exchange onto the same name, or between links to the same
	// file, does nothing. Like Linux, check this before the write permission
	// checks.
	if replacedErr == nil && opts.Flags&linux.RENAME_NOREPLACE == 0 {
		if renamed.isDir() {
			if renamed == replaced {
				return nil
			}
		} else if !opts.MustBeDir && !rp.MustBeDir() && fs.isSameUpperFileLocked(ctx, oldParent, oldName, renamed, newParent, newName, replaced) {
			return nil
		}
	}
	if err := oldParent.checkPermissions(creds, vfs.MayWrite); err != nil {
		return err
	}
	if err := oldParent.mayDelete(creds, renamed); err != nil {
		return err
	}
	if renamed.isDir() {
		if renamed == newParent || genericIsAncestorDentry(fs, renamed, newParent) {
			return linuxerr.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
	} else {
		if !exchange && (opts.MustBeDir || rp.MustBeDir()) {
			return linuxerr.ENOTDIR
		}
	}

	if oldParent != newParent {
		if err := newParent.checkPermissions(creds, vfs.MayWrite); err != nil {
			return err
		}
	}
	if oldParent.vfsd.IsDead() || newParent.vfsd.IsDead() {
		return linuxerr.ENOENT
	}
	if replacedErr != nil && !linuxerr.Equals(linuxerr.ENOENT, replacedErr) {
		return replacedErr
	}
	var (
		replacedVFSD      *vfs.Dentry
		replacedWhiteouts map[string]bool
	)
	if replaced != nil {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		if err := newParent.mayDelete(creds, replaced); err != nil {
			return err
		}
		replacedVFSD = &replaced.vfsd
		if exchange {
			// The exchanged files may differ in type, and a directory being
			// exchanged may be non-empty; but exchanging a file with an
			// ancestor directory would disconnect the latter from the tree.
			if genericIsAncestorDentry(fs, replaced, renamed) {
				return linuxerr.EINVAL
			}
			if rp.MustBeDir() && !replaced.isDir() {
				return linuxerr.ENOTDIR
			}
			if opts.MustBeDir && !renamed.isDir() {
				return linuxerr.ENOTDIR
			}
			if oldParent != newParent && replaced.isDir() {
				// Writability is needed to change replaced's "..".
				if err := replaced.checkPermissions(creds, vfs.MayWrite); err != nil {
					return err
				}
			}
		} else if replaced.isDir() {
			if !renamed.isDir() {
				return linuxerr.EISDIR
			}
			if genericIsAncestorDentry(fs, replaced, renamed) {
				return linuxerr.ENOTEMPTY
			}
			replacedDirIdx := replaced.dirLockIndex(dirLockD1Replaced)
			replaced.dirMu.NestedLock(replacedDirIdx)
			defer replaced.dirMu.NestedUnlock(replacedDirIdx)
			if replacedWhiteouts, err = replaced.collectWhiteoutsForRmdirLocked(ctx); err != nil {
				return err
			}
		} else {
			if rp.MustBeDir() || renamed.isDir() {
				return linuxerr.ENOTDIR
			}
		}
	} else if exchange {
		// RENAME_EXCHANGE requires that the target file exist.
		return linuxerr.ENOENT
	}

	if oldParent == newParent && oldName == newName {
		return nil
	}

	// renamed and oldParent need to be copied-up before they're renamed on the
	// upper layer.
	if err := renamed.copyUpLocked(ctx); err != nil {
		return err
	}
	// If renamed is a directory, all of its descendants need to be copied-up
	// before they're renamed on the upper layer.
	if renamed.isDir() {
		if err := renamed.copyUpDescendantsLocked(ctx, &ds); err != nil {
			return err
		}
	}
	// newParent must be copied-up before it can contain renamed on the upper
	// layer.
	if err := newParent.copyUpLocked(ctx); err != nil {
		return err
	}
	if exchange {
		// replaced is also renamed on the upper layer, so it (and all of its
		// descendants if it's a directory) must be copied-up too.
		if err := replaced.copyUpLocked(ctx); err != nil {
			return err
		}
		if replaced.isDir() {
			replacedDirIdx := replaced.dirLockIndex(dirLockD1Replaced)
			replaced.dirMu.NestedLock(replacedDirIdx)
			err := replaced.copyUpDescendantsLocked(ctx, &ds)
			replaced.dirMu.NestedUnlock(replacedDirIdx)
			if err != nil {
				return err
			}
		}
	} else if replaced != nil {
		// replaced doesn't need to be copied-up, but we do need to serialize
		// with copy-up. A copy-up for write unlocks renameMu while it copies
		// data, so it may have finished just now. Read the layer only under
		// copyMu.
		replaced.copyMu.RLock()
		defer replaced.copyMu.RUnlock()
		replacedLayer = replaced.topLookupLayer()
	}

	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	handle, err := vfsObj.PrepareRenameDentry(ctx, mntns, &renamed.vfsd, replacedVFSD)
	if err != nil {
		return err
	}
	// Dentry.mu of renamed and replaced are locked. If renameUpperLocked
	// panics, unlock them before the deferred functions above run, because
	// some of them lock Dentry.mu.
	prepared := true
	defer func() {
		if prepared {
			vfsObj.AbortRenameDentry(&handle, &renamed.vfsd, replacedVFSD)
		}
	}()
	var layerCtx context.Context
	layerCtx, layerOp = vfs.WithLayerOperation(ctx)
	err = fs.renameUpperLocked(layerCtx, oldParent, oldName, renamed, newParent, newName, replaced, replacedLayer, replacedWhiteouts, exchange)
	prepared = false
	if err != nil {
		vfsObj.AbortRenameDentry(&handle, &renamed.vfsd, replacedVFSD)
		return err
	}

	if exchange {
		// Below this point, renamed is at newName and replaced is at oldName.
		// Commit the exchange and update the overlay filesystem tree.
		vfsObj.RenameBegin(&handle)
		genericSetParentAndName(fs, renamed, newParent, newName)
		genericSetParentAndName(fs, replaced, oldParent, oldName)
		// References held by renamed and replaced on their parents are
		// exchanged as well; the counts on each parent are unchanged.
		oldParent.children[oldName] = replaced
		newParent.children[newName] = renamed
		oldParent.dirents = nil
		newParent.dirents = nil
		vfsObj.CommitRenameExchangeDentry(&handle, &renamed.vfsd, replacedVFSD)

		nctx := withDropList(ctx, &ds)
		vfs.InotifyRename(nctx, &renamed.watches, &oldParent.watches, &newParent.watches, oldName, newName, renamed.isDir())
		vfs.InotifyRename(nctx, &replaced.watches, &newParent.watches, &oldParent.watches, newName, oldName, replaced.isDir())
		return nil
	}

	// Below this point, the renamed dentry is now at newName, and anything we
	// replaced is gone forever. Commit the rename and update the overlay
	// filesystem tree.
	vfsObj.RenameBegin(&handle)
	delete(oldParent.children, oldName)
	if replaced != nil {
		// Lower dentries of replaced are not reachable from the overlay anymore.
		// NOTE(b/237573779): Ask lower filesystem to release resources for this
		// dentry whenever possible to reduce resource usage.
		for _, replaceLower := range replaced.lowerVDs {
			replaceLower.Dentry().MarkEvictable()
		}
		ds = appendDentry(ds, replaced)
	}
	if oldParent != newParent {
		newParent.dirents = nil
		// This can't drop the last reference on oldParent because one is held
		// by oldParentVD, so lock recursion is impossible.
		oldParent.DecRef(ctx)
		ds = appendDentry(ds, oldParent)
		newParent.IncRef()
	}
	genericSetParentAndName(fs, renamed, newParent, newName)
	if newParent.children == nil {
		newParent.children = make(map[string]*dentry)
	}
	newParent.children[newName] = renamed
	oldParent.dirents = nil
	toDecRef = vfsObj.CommitRenameReplaceDentry(ctx, &handle, &renamed.vfsd, replacedVFSD)

	vfs.InotifyRename(withDropList(ctx, &ds), &renamed.watches, &oldParent.watches, &newParent.watches, oldName, newName, renamed.isDir())
	return nil
}

// renameUpperLocked renames or exchanges renamed on the upper layer. If
// replaced is a directory that the rename replaces, replacedWhiteouts
// are the whiteouts in it, as collectWhiteoutsForRmdirLocked returns them. If
// renameUpperLocked returns an error, the overlay is unchanged.
//
// Preconditions:
//   - fs.renameMu must be locked for writing.
//   - oldParent.dirMu and newParent.dirMu must be locked.
//   - renamed, oldParent and newParent have been copied up. If exchange is
//     true, replaced has been copied up.
func (fs *filesystem) renameUpperLocked(ctx context.Context, oldParent *dentry, oldName string, renamed *dentry, newParent *dentry, newName string, replaced *dentry, replacedLayer lookupLayer, replacedWhiteouts map[string]bool, exchange bool) error {
	oldDir := oldParent.upperVD
	newDir := newParent.upperVD

	// A directory that moves to a merged directory must not merge with the
	// lower layer directories there. Its descendants have been copied up, so
	// making it opaque before the move does not change its contents.
	if renamed.isDir() && len(newParent.lowerVDs) > 0 {
		pop := layerChildPop(oldDir, oldName)
		if err := fs.setOpaque(ctx, &pop); err != nil {
			return opaqueError(err)
		}
	}
	if exchange && replaced.isDir() && len(oldParent.lowerVDs) > 0 {
		pop := layerChildPop(newDir, newName)
		if err := fs.setOpaque(ctx, &pop); err != nil {
			return opaqueError(err)
		}
	}

	if exchange {
		return fs.renameUpper(ctx, oldDir, oldName, newDir, newName, linux.RENAME_EXCHANGE)
	}

	needWhiteout := fs.lowerLayersHaveChildLocked(ctx, oldParent, oldName)
	if renamed.isDir() && (replacedLayer == lookupLayerUpper || replacedLayer == lookupLayerUpperWhiteout) {
		// A rename cannot replace a whiteout with a directory, or replace a
		// directory that contains whiteouts, so exchange them.
		var replacedUpperVD vfs.VirtualDentry
		if replaced != nil {
			replacedUpperVD = replaced.upperVD
		}
		return fs.renameDirOverUpperLocked(ctx, oldDir, oldName, newDir, newName, replacedLayer, replacedUpperVD, replacedWhiteouts, needWhiteout)
	}

	// The rename replaces the file at newName on the upper layer, if any.
	if !needWhiteout {
		return fs.renameUpper(ctx, oldDir, oldName, newDir, newName, 0)
	}
	if fs.opts.PrivateUpper && (replacedLayer == lookupLayerNone || replacedLayer == lookupLayerLower) {
		// No other process can see the upper layer, and no file is at newName
		// on the upper layer. Thus a rename back to oldName undoes the rename.
		if err := fs.renameUpper(ctx, oldDir, oldName, newDir, newName, 0); err != nil {
			return err
		}
		pop := layerChildPop(oldDir, oldName)
		if err := CreateWhiteout(ctx, fs.vfsfs.VirtualFilesystem(), fs.creds, &pop); err != nil {
			if undoErr := fs.renameUpper(ctx, newDir, newName, oldDir, oldName, 0); undoErr != nil {
				panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to undo rename after whiteout creation failure: %v", undoErr))
			}
			return err
		}
		return nil
	}
	// Exchange the file with a new whiteout, so that oldName is never missing
	// on the upper layer. Then move the file, which has the temporary name of
	// the whiteout, to newName.
	tmpName, err := fs.createTempWhiteout(ctx, oldDir)
	if err != nil {
		return err
	}
	if err := fs.exchangeUpper(ctx, oldDir, tmpName, oldDir, oldName); err != nil {
		fs.unlinkTemp(ctx, oldDir, tmpName)
		return err
	}
	if err := fs.renameUpper(ctx, oldDir, tmpName, newDir, newName, 0); err != nil {
		if undoErr := fs.exchangeUpper(ctx, oldDir, tmpName, oldDir, oldName); undoErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to undo exchange after RenameAt failure: %v", undoErr))
		}
		fs.unlinkTemp(ctx, oldDir, tmpName)
		return err
	}
	fs.forgetTemp(tmpName)
	return nil
}

// renameDirOverUpperLocked renames the directory oldName in the upper layer
// directory oldDir to newName in the upper layer directory newDir, where there
// is a whiteout (replacedLayer == lookupLayerUpperWhiteout) or a directory that
// contains only the whiteouts replacedWhiteouts (replacedLayer ==
// lookupLayerUpper), which is replacedUpperVD. If needWhiteout is true,
// renameDirOverUpperLocked leaves a whiteout at oldName. If
// renameDirOverUpperLocked returns an error, the upper layer is unchanged.
//
// Preconditions: Same as renameUpperLocked.
func (fs *filesystem) renameDirOverUpperLocked(ctx context.Context, oldDir vfs.VirtualDentry, oldName string, newDir vfs.VirtualDentry, newName string, replacedLayer lookupLayer, replacedUpperVD vfs.VirtualDentry, replacedWhiteouts map[string]bool, needWhiteout bool) error {
	var tmpName string
	if needWhiteout && replacedLayer == lookupLayerUpper {
		var err error
		if tmpName, err = fs.createTempWhiteout(ctx, oldDir); err != nil {
			return err
		}
	}
	if err := fs.exchangeUpper(ctx, oldDir, oldName, newDir, newName); err != nil {
		if tmpName != "" {
			fs.unlinkTemp(ctx, oldDir, tmpName)
		}
		return err
	}
	// Now the whiteout or the replaced directory is at oldName.
	if replacedLayer == lookupLayerUpperWhiteout {
		if !needWhiteout {
			// No lower layer has a file at oldName, so the whiteout hides
			// nothing.
			pop := layerChildPop(oldDir, oldName)
			if err := fs.vfsfs.VirtualFilesystem().UnlinkAt(ctx, fs.creds, &pop); err != nil {
				log.Warningf("overlay: failed to remove whiteout %q from the upper layer: %v", oldName, err)
			}
		}
		return nil
	}
	var err error
	if needWhiteout {
		// Exchange the replaced directory with the new whiteout.
		err = fs.exchangeUpper(ctx, oldDir, tmpName, oldDir, oldName)
	} else {
		// Move the replaced directory to a temporary name. As in
		// exchangeUpper, do not use RENAME_NOREPLACE.
		tmpName, err = fs.createTemp(oldDir, func(pop vfs.PathOperation) error {
			src := layerChildPop(oldDir, oldName)
			return fs.vfsfs.VirtualFilesystem().RenameAt(ctx, fs.creds, &src, &pop, &vfs.RenameOptions{})
		})
	}
	if err != nil {
		if undoErr := fs.exchangeUpper(ctx, oldDir, oldName, newDir, newName); undoErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to undo exchange after RenameAt failure: %v", undoErr))
		}
		if needWhiteout {
			fs.unlinkTemp(ctx, oldDir, tmpName)
		}
		return err
	}
	// The replaced directory is at tmpName.
	fs.removeTempDir(ctx, oldDir, tmpName, replacedUpperVD, replacedWhiteouts)
	return nil
}

// opaqueError converts an error from setOpaque for a directory that moves to a
// merged directory. Like Linux, it returns EXDEV if the upper layer does not
// allow the xattr, so that applications copy the directory instead.
func opaqueError(err error) error {
	return xattrError(err, linuxerr.EXDEV)
}

// xattrError returns xerr if err shows that the upper layer does not allow
// overlay xattrs (for example, trusted xattrs in a user namespace), and err
// otherwise.
func xattrError(err, xerr error) error {
	if linuxerr.Equals(linuxerr.EOPNOTSUPP, err) || linuxerr.Equals(linuxerr.EPERM, err) {
		return xerr
	}
	return err
}

// isSameUpperFileLocked returns true if renamed (oldName in oldParent) and
// target (newName in newParent) are the same file on the upper layer. Files
// on lower layers are different files in the overlay, even if they are links
// to the same file on a lower layer.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - oldParent.dirMu and newParent.dirMu must be locked.
func (fs *filesystem) isSameUpperFileLocked(ctx context.Context, oldParent *dentry, oldName string, renamed *dentry, newParent *dentry, newName string, target *dentry) bool {
	if renamed == target {
		return true
	}
	if target.isDir() || !renamed.isCopiedUp() || !target.isCopiedUp() {
		return false
	}
	// Non-directory files have the device and inode numbers of the file on
	// the topmost layer. Compare them first, to stat the upper layer only if
	// the files are probably the same.
	if renamed.ino.Load() != target.ino.Load() || renamed.devMajor.Load() != target.devMajor.Load() || renamed.devMinor.Load() != target.devMinor.Load() {
		return false
	}
	vfsObj := fs.vfsfs.VirtualFilesystem()
	opts := vfs.StatOptions{Mask: linux.STATX_INO | linux.STATX_NLINK}
	oldpop := layerChildPop(oldParent.upperVD, oldName)
	stat1, err := vfsObj.StatAt(ctx, fs.creds, &oldpop, &opts)
	if err != nil {
		return false
	}
	newpop := layerChildPop(newParent.upperVD, newName)
	stat2, err := vfsObj.StatAt(ctx, fs.creds, &newpop, &opts)
	if err != nil {
		return false
	}
	// On an overlayfs, different files can have the same device and inode
	// numbers, but links to one file have the same link count, which is at
	// least 2.
	const mask = linux.STATX_INO | linux.STATX_NLINK
	return stat1.Mask&mask == mask && stat2.Mask&mask == mask && stat1.Ino == stat2.Ino && stat1.DevMajor == stat2.DevMajor && stat1.DevMinor == stat2.DevMinor && stat1.Nlink >= 2 && stat1.Nlink == stat2.Nlink
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	// We need to DecRef outside of fs.mu because forgetting a dead mountpoint
	// could result in this filesystem being released which acquires fs.mu.
	var toDecRef []refs.RefCounter
	var layerOp *vfs.LayerOperation
	defer func() {
		layerOp.Finish(ctx)
		for _, ref := range toDecRef {
			ref.DecRef(ctx)
		}
	}()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	parentDirIdx := parent.dirLockIndex(dirLockD1)
	parent.dirMu.NestedLock(parentDirIdx)
	defer parent.dirMu.NestedUnlock(parentDirIdx)

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	// We need a dentry representing the child directory being removed in order
	// to verify that it's empty.
	child, _, err := fs.getChildLocked(ctx, parent, name, &ds)
	if err != nil {
		return err
	}
	if !child.isDir() {
		return linuxerr.ENOTDIR
	}
	if err := parent.mayDelete(rp.Credentials(), child); err != nil {
		return err
	}
	childDirIdx := child.dirLockIndex(dirLockD1Child)
	child.dirMu.NestedLock(childDirIdx)
	defer child.dirMu.NestedUnlock(childDirIdx)
	whiteouts, err := child.collectWhiteoutsForRmdirLocked(ctx)
	if err != nil {
		return err
	}
	child.copyMu.RLock()
	defer child.copyMu.RUnlock()
	if err := vfsObj.PrepareDeleteDentry(ctx, mntns, &child.vfsd); err != nil {
		return err
	}
	// Dentry.mu of child is locked until CommitDeleteDentry or
	// AbortDeleteDentry. If a layer operation panics, unlock it before the
	// deferred functions above run, because some of them lock Dentry.mu.
	prepared := true
	defer func() {
		if prepared {
			vfsObj.AbortDeleteDentry(&child.vfsd)
		}
	}()
	var layerCtx context.Context
	layerCtx, layerOp = vfs.WithLayerOperation(ctx)

	switch {
	case child.upperVD.Ok() && fs.lowerLayersHaveChildLocked(layerCtx, parent, name):
		// Replace the directory with a whiteout in one exchange. Then remove the
		// directory, which now has a temporary name.
		var tmpName string
		if tmpName, err = fs.createTempWhiteout(layerCtx, parent.upperVD); err != nil {
			break
		}
		if err = fs.exchangeUpper(layerCtx, parent.upperVD, tmpName, parent.upperVD, name); err != nil {
			fs.unlinkTemp(layerCtx, parent.upperVD, tmpName)
			break
		}
		fs.removeTempDir(layerCtx, parent.upperVD, tmpName, child.upperVD, whiteouts)

	case child.upperVD.Ok():
		// No lower layer has a file at name, so no whiteout is necessary, and
		// whiteouts in the directory hide nothing.
		err = fs.removeUpperDir(layerCtx, parent.upperVD, name, child.upperVD, whiteouts)

	default:
		// The directory is only on lower layers.
		pop := layerChildPop(parent.upperVD, name)
		err = CreateWhiteout(layerCtx, vfsObj, fs.creds, &pop)
	}
	prepared = false
	if err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return err
	}

	toDecRef = vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
	delete(parent.children, name)
	fs.releaseDirIno(child.dirInoHash)
	ds = appendDentry(ds, child)
	parent.dirents = nil
	nctx := withDropList(ctx, &ds)
	// Linux sends the parent's IN_DELETE|IN_ISDIR at rmdir() time, but
	// defers the child's IN_DELETE_SELF/IN_IGNORED until the last ref is
	// dropped. Emit the child notifications now only when no extra refs
	// remain; otherwise defer to destroyLocked().
	if child.refs.Load() == 0 {
		child.watches.HandleDeletion(nctx)
	}
	parent.watches.Notify(nctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0 /* cookie */, vfs.InodeEvent, true /* unlinked */)
	return nil
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}
	d.IncRef()
	defer d.DecRef(ctx)
	err = d.setStatLocked(ctx, rp, opts)
	if err == nil {
		if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
			d.InotifyWithParent(withDropList(ctx, &ds), ev, 0 /* cookie */, vfs.InodeEvent)
		}
	}
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	return err
}

// isNoopChown returns true if opts only sets d's owner to its current value
// and would not clear setid bits, which the gofer filesystem also skips.
func (d *dentry) isNoopChown(opts *vfs.SetStatOptions) bool {
	stat := &opts.Stat
	mode := d.mode.Load()
	setsMore := stat.Mask&^(linux.STATX_UID|linux.STATX_GID) != 0
	changesUID := stat.Mask&linux.STATX_UID != 0 && stat.UID != d.uid.Load()
	changesGID := stat.Mask&linux.STATX_GID != 0 && stat.GID != d.gid.Load()
	clearsSetid := opts.ClearPrivs && vfs.ClearSUIDAndSGID(mode) != mode
	if setsMore || changesUID || changesGID || clearsSetid {
		return false
	}
	return true
}

// Preconditions: d.fs.renameMu must be held for reading, and the caller must hold a reference on d.
func (d *dentry) setStatLocked(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	mode := linux.FileMode(d.mode.Load())
	if err := vfs.CheckSetStat(ctx, rp.Credentials(), &opts, mode, d.accessACL.Load(), auth.KUID(d.uid.Load()), auth.KGID(d.gid.Load())); err != nil {
		return err
	}
	if opts.NeedWritePerm {
		// truncate(2), unlike ftruncate(2), acquires write access to the file
		// and so fails with ETXTBSY if it is being executed. See
		// fs/open.c:do_sys_truncate().
		if err := d.writeCount.CheckWrite(); err != nil {
			return err
		}
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if !d.isCopiedUp() && d.isNoopChown(&opts) {
		return nil
	}
	if err := d.copyUpForWriteLocked(ctx); err != nil {
		return err
	}
	// Changes to d's attributes are serialized by d.copyMu.
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	upperPop := vfs.PathOperation{
		Root:  d.upperVD,
		Start: d.upperVD,
	}
	if err := vfsObj.SetStatAt(ctx, d.fs.creds, &upperPop, &opts); err != nil {
		return err
	}

	// Changing owners or truncating may clear one or both of the setuid and
	// setgid bits, so we may have to update opts before setting d.mode.
	hadSetid := d.mode.Load()&(linux.S_ISUID|linux.S_ISGID) != 0
	setsMode := opts.Stat.Mask&linux.STATX_MODE != 0
	mayClearSetid := opts.Stat.Mask&(linux.STATX_UID|linux.STATX_GID|linux.STATX_SIZE) != 0
	if (hadSetid || setsMode) && mayClearSetid {
		stat, err := vfsObj.StatAt(ctx, d.fs.creds, &upperPop, &vfs.StatOptions{
			Mask: linux.STATX_MODE,
		})
		if err != nil {
			return err
		}
		opts.Stat.Mode = stat.Mode
		opts.Stat.Mask |= linux.STATX_MODE
	}

	d.updateAfterSetStatLocked(&opts)
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	var d *dentry
	if rp.Done() {
		d = rp.Start().Impl().(*dentry)
	} else {
		var ds *[]*dentry
		fs.renameMu.NestedRLock(fs.renameLockIndex())
		defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		var err error
		d, err = fs.resolveLocked(ctx, rp, &ds)
		if err != nil {
			return linux.Statx{}, err
		}
	}

	var stat linux.Statx
	if layerMask := opts.Mask &^ statInternalMask; layerMask != 0 {
		layerVD := d.topLayer()
		var err error
		stat, err = fs.vfsfs.VirtualFilesystem().StatAt(ctx, fs.creds, &vfs.PathOperation{
			Root:  layerVD,
			Start: layerVD,
		}, &vfs.StatOptions{
			Mask: layerMask,
			Sync: opts.Sync,
		})
		if err != nil {
			return linux.Statx{}, err
		}
		// The layer's STATX_ATTR_MOUNT_ROOT refers to the layer mount, not
		// the overlay mount.
		stat.Attributes &^= linux.STATX_ATTR_MOUNT_ROOT
		stat.AttributesMask &^= linux.STATX_ATTR_MOUNT_ROOT
	}
	d.statInternalTo(ctx, &opts, &stat)
	rp.AddMountRootAttr(&d.vfsd, &stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	_, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return linux.Statfs{}, err
	}
	return fs.statFS(ctx)
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, createNonDirectory, func(parent *dentry, childName string, haveUpperWhiteout bool, ds **[]*dentry) error {
		vfsObj := fs.vfsfs.VirtualFilesystem()
		createCreds := parent.credsForCreate(rp.Credentials(), parent.isSGIDSet())
		create := func(pop vfs.PathOperation) error {
			return vfsObj.SymlinkAt(ctx, createCreds, &pop, target)
		}
		return fs.createUpperLocked(ctx, parent, childName, haveUpperWhiteout, false /* isDir */, create)
	})
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	// We need to DecRef outside of fs.renameMu because forgetting a dead
	// mountpoint could result in this filesystem being released which acquires
	// fs.renameMu.
	var toDecRef []refs.RefCounter
	var layerOp *vfs.LayerOperation
	defer func() {
		layerOp.Finish(ctx)
		for _, ref := range toDecRef {
			ref.DecRef(ctx)
		}
	}()
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	start := rp.Start().Impl().(*dentry)
	parent, err := fs.walkParentDirLocked(ctx, rp, start, &ds)
	if err != nil {
		return err
	}
	if err := parent.checkPermissions(rp.Credentials(), vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return err
	}
	defer rp.Mount().EndWrite()
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	dirIdx := parent.dirLockIndex(dirLockD1)
	parent.dirMu.NestedLock(dirIdx)
	defer parent.dirMu.NestedUnlock(dirIdx)

	if rp.MustBeDir() {
		// The trailing slash makes this fail regardless, but the error depends
		// on whether the child exists and is a directory. Check before copying
		// up the parent, so that a failing unlink doesn't copy it up.
		child, _, err := fs.getChildLocked(ctx, parent, name, &ds)
		if err != nil {
			return err
		}
		if child.isDir() {
			return linuxerr.EISDIR
		}
		return linuxerr.ENOTDIR
	}

	// Ensure that parent is copied-up before potentially holding child.copyMu
	// below.
	if err := parent.copyUpLocked(ctx); err != nil {
		return err
	}

	// We need a dentry representing the child being removed in order to verify
	// that it's not a directory.
	child, _, err := fs.getChildLocked(ctx, parent, name, &ds)
	if err != nil {
		return err
	}
	if child.isDir() {
		return linuxerr.EISDIR
	}
	if err := parent.mayDelete(rp.Credentials(), child); err != nil {
		return err
	}
	// Hold child.copyMu to prevent it from being copied-up during
	// deletion.
	child.copyMu.RLock()
	defer child.copyMu.RUnlock()
	// A copy-up running without renameMu may have finished just now, so read
	// the layer only under copyMu.
	childLayer := child.topLookupLayer()
	if err := vfsObj.PrepareDeleteDentry(ctx, mntns, &child.vfsd); err != nil {
		return err
	}
	// Dentry.mu of child is locked until CommitDeleteDentry or
	// AbortDeleteDentry. If a layer operation panics, unlock it before the
	// deferred functions above run, because some of them lock Dentry.mu.
	prepared := true
	defer func() {
		if prepared {
			vfsObj.AbortDeleteDentry(&child.vfsd)
		}
	}()
	var layerCtx context.Context
	layerCtx, layerOp = vfs.WithLayerOperation(ctx)

	pop := layerChildPop(parent.upperVD, name)
	switch {
	case childLayer == lookupLayerUpper && fs.lowerLayersHaveChildLocked(layerCtx, parent, name):
		// Replace the file on the upper layer with a whiteout in one rename.
		err = fs.replaceWithWhiteout(layerCtx, parent.upperVD, name)
	case childLayer == lookupLayerUpper:
		// No lower layer has a file at name, so no whiteout is necessary.
		err = vfsObj.UnlinkAt(layerCtx, fs.creds, &pop)
	default:
		// The file is only on lower layers.
		err = CreateWhiteout(layerCtx, vfsObj, fs.creds, &pop)
	}
	prepared = false
	if err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return err
	}

	toDecRef = vfsObj.CommitDeleteDentry(ctx, &child.vfsd)
	delete(parent.children, name)
	if !child.isDir() {
		// Once a whiteout is created, non-directory dentries on the lower layers
		// are no longer reachable from the overlayfs. Ask filesystems to release
		// their resources whenever possible.
		for _, lowerDentry := range child.lowerVDs {
			lowerDentry.Dentry().MarkEvictable()
		}
	}
	ds = appendDentry(ds, child)
	vfs.InotifyRemoveChild(withDropList(ctx, &ds), &child.watches, &parent.watches, name)
	parent.dirents = nil
	return nil
}

// isOverlayXattr returns whether the given extended attribute configures the
// overlay.
func (fs *filesystem) isOverlayXattr(name string) bool {
	return strings.HasPrefix(name, fs.xattrPrefix)
}

// ListXattrAt implements vfs.FilesystemImpl.ListXattrAt.
func (fs *filesystem) ListXattrAt(ctx context.Context, rp *vfs.ResolvingPath, size uint64) ([]string, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}

	return fs.listXattr(ctx, d, rp.Credentials())
}

func (fs *filesystem) listXattr(ctx context.Context, d *dentry, creds *auth.Credentials) ([]string, error) {
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	top := d.topLayer()
	// A bounded size gets FUSE to return names; the syscall layer checks size.
	names, err := vfsObj.ListXattrAt(ctx, fs.creds, &vfs.PathOperation{Root: top, Start: top}, linux.XATTR_LIST_MAX)
	if err != nil {
		return nil, err
	}

	// Filter out overlay attributes and hidden trusted.* names.
	canListTrusted := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	n := 0
	for _, name := range names {
		if fs.isOverlayXattr(name) {
			continue
		}
		if !canListTrusted && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names[n] = name
		n++
	}
	return names[:n], err
}

// GetXattrAt implements vfs.FilesystemImpl.GetXattrAt.
func (fs *filesystem) GetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetXattrOptions) (string, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return "", err
	}

	return fs.getXattr(ctx, d, rp.Credentials(), &opts)
}

func (fs *filesystem) getXattr(ctx context.Context, d *dentry, creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	// Handle POSIX access ACL xattr
	if strings.HasPrefix(opts.Name, linux.XATTR_SYSTEM_PREFIX) {
		// Handle POSIX ACL xattrs
		xattr, err := vfs.ACLGetXattr(creds, opts, linux.FileMode(d.mode.Load()), d.accessACL.Load(), d.defaultACL.Load())
		return xattr, err
	}

	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayRead); err != nil {
		return "", err
	}

	// Return EOPNOTSUPP when fetching an overlay attribute.
	// See fs/overlayfs/super.c:ovl_own_xattr_get().
	if fs.isOverlayXattr(opts.Name) {
		return "", linuxerr.EOPNOTSUPP
	}

	// Analogous to fs/overlayfs/super.c:ovl_other_xattr_get().
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	top := d.topLayer()
	return vfsObj.GetXattrAt(ctx, creds, &vfs.PathOperation{Root: top, Start: top}, opts)
}

// SetXattrAt implements vfs.FilesystemImpl.SetXattrAt.
func (fs *filesystem) SetXattrAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetXattrOptions) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}

	err = fs.setXattrLocked(ctx, d, rp.Mount(), rp.Credentials(), &opts)
	if err == nil {
		d.InotifyWithParent(withDropList(ctx, &ds), linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent)
	}
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	return err
}

// Precondition: fs.renameMu must be locked, d.copyMu must be unlocked.
func (fs *filesystem) setXattrLocked(ctx context.Context, d *dentry, mnt *vfs.Mount, creds *auth.Credentials, opts *vfs.SetXattrOptions) error {
	// Handle POSIX ACLs separately
	if strings.HasPrefix(opts.Name, linux.XATTR_SYSTEM_PREFIX) {
		acl, aclType, err := vfs.ACLSetXattr(creds, opts, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()))
		if err != nil {
			return err
		}

		// Set the appropriate POSIX ACL
		_, _, err = fs.setPosixACLLocked(ctx, d, creds, mnt, aclType, acl, true /* clearSGID */)
		return err
	}

	if err := d.checkXattrPermissions(creds, opts.Name, vfs.MayWrite); err != nil {
		return err
	}

	// Return EOPNOTSUPP when setting an overlay attribute.
	// See fs/overlayfs/super.c:ovl_own_xattr_set().
	if fs.isOverlayXattr(opts.Name) {
		return linuxerr.EOPNOTSUPP
	}

	// Analogous to fs/overlayfs/super.c:ovl_other_xattr_set().
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	// Notably, we use the caller's creds here rather than the filesystem's creds,
	// since setting some xattrs includes additional UID/GID and userns-related checks
	// and translations.
	return vfsObj.SetXattrAt(ctx, creds, &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}, opts)
}

// RemoveXattrAt implements vfs.FilesystemImpl.RemoveXattrAt.
func (fs *filesystem) RemoveXattrAt(ctx context.Context, rp *vfs.ResolvingPath, name string) error {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
		return err
	}

	err = fs.removeXattrLocked(ctx, d, rp.Mount(), rp.Credentials(), name)
	if err == nil {
		d.InotifyWithParent(withDropList(ctx, &ds), linux.IN_ATTRIB, 0 /* cookie */, vfs.InodeEvent)
	}
	fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	return err
}

// Precondition: fs.renameMu must be locked, d.copyMu must be unlocked.
func (fs *filesystem) removeXattrLocked(ctx context.Context, d *dentry, mnt *vfs.Mount, creds *auth.Credentials, name string) error {
	if strings.HasPrefix(name, linux.XATTR_SYSTEM_PREFIX) {
		aclType, err := vfs.ACLRemoveXattr(creds, name, linux.FileMode(d.mode.Load()), auth.KUID(d.uid.Load()))
		if err != nil {
			return err
		}

		// Clear the appropriate POSIX ACL
		_, _, err = fs.setPosixACLLocked(ctx, d, creds, mnt, aclType, nil, true /* clearSGID */)
		return err
	}

	if err := d.checkXattrPermissions(creds, name, vfs.MayWrite); err != nil {
		return err
	}

	// Like SetXattrAt, return EOPNOTSUPP when removing an overlay attribute.
	// Linux passes the remove request to xattr_handler->set.
	// See fs/xattr.c:vfs_removexattr().
	if fs.isOverlayXattr(name) {
		return linuxerr.EOPNOTSUPP
	}

	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return err
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	return vfsObj.RemoveXattrAt(ctx, creds, &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}, name)
}

// GetPosixACLAt implements vfs.FilesystemImpl.GetPosixACLAt.
func (fs *filesystem) GetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType) (*vfs.PosixACL, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, err
	}
	return fs.getPosixACLLocked(ctx, d, t)
}

func (fs *filesystem) getPosixACLLocked(ctx context.Context, d *dentry, t vfs.ACLType) (*vfs.PosixACL, error) {
	switch t {
	case vfs.AccessACL:
		return d.accessACL.Load(), nil
	case vfs.DefaultACL:
		return d.defaultACL.Load(), nil
	default:
		return nil, linuxerr.EINVAL
	}
}

// SetPosixACLAt implements vfs.FilesystemImpl.SetPosixACLAt.
func (fs *filesystem) SetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType, acl *vfs.PosixACL, clearSGID bool) (*vfs.PosixACL, linux.FileMode, error) {
	var ds *[]*dentry
	fs.renameMu.NestedRLock(fs.renameLockIndex())
	defer fs.renameMuRUnlockAndCheckDrop(ctx, &ds)
	d, err := fs.resolveLocked(ctx, rp, &ds)
	if err != nil {
		return nil, 0, err
	}
	newACL, mode, err := fs.setPosixACLLocked(ctx, d, rp.Credentials(), rp.Mount(), t, acl, clearSGID)
	return newACL, mode, err
}

// Precondition: fs.renameMu must be locked, d.copyMu must be unlocked.
func (fs *filesystem) setPosixACLLocked(ctx context.Context, d *dentry, creds *auth.Credentials, mnt *vfs.Mount, t vfs.ACLType, acl *vfs.PosixACL, clearSGID bool) (*vfs.PosixACL, linux.FileMode, error) {
	// Skip ACL update when clearing an already-missing ACL (to prevent unnecessary copy-up)
	oldACL, err := fs.getPosixACLLocked(ctx, d, t)
	if err != nil {
		return nil, 0, err
	}
	// Take copyMu to check d.upperVD. Technically d could be copied up between here and the later
	// call to d.copyUpLocked(), but this would have no effect.
	d.copyMu.RLock()
	copiedUp := d.upperVD.Ok()
	d.copyMu.RUnlock()
	if acl == nil && oldACL == nil && !copiedUp {
		mode := linux.FileMode(d.mode.Load())
		if t == vfs.DefaultACL && !mode.IsDir() {
			return nil, 0, nil
		}
		// ENODATA to match Linux.
		return nil, 0, linuxerr.ENODATA
	}

	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, 0, err
	}
	defer mnt.EndWrite()
	if err := d.copyUpLocked(ctx); err != nil {
		return nil, 0, err
	}
	vfsObj := d.fs.vfsfs.VirtualFilesystem()
	upperPop := &vfs.PathOperation{Root: d.upperVD, Start: d.upperVD}

	// First, set the ACL on the underlying filesystem
	d.copyMu.Lock()
	defer d.copyMu.Unlock()
	newACL, mode, err := vfsObj.SetPosixACLAt(ctx, creds, upperPop, t, acl, clearSGID)
	if err != nil {
		return nil, 0, err
	}

	// Next, update the ACL in our dentry
	switch t {
	case vfs.AccessACL:
		d.accessACL.Store(newACL)
		d.mode.Store(uint32(mode))
	case vfs.DefaultACL:
		d.defaultACL.Store(newACL)
	}

	return newACL, mode, nil
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	return genericPrependPath(fs, vfsroot, vd.Mount(), vd.Dentry().Impl().(*dentry), b)
}

// IsDescendant implements vfs.FilesystemImpl.IsDescendant.
func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	return genericIsDescendant(fs, vfsroot.Dentry(), vd.Dentry().Impl().(*dentry))
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	// Return the mount options from the topmost layer.
	var vd vfs.VirtualDentry
	if fs.opts.UpperRoot.Ok() {
		vd = fs.opts.UpperRoot
	} else {
		vd = fs.opts.LowerRoots[0]
	}
	return vd.Mount().Filesystem().Impl().MountOptions()
}
