// Copyright 2026 The gVisor Authors.
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
	"encoding/hex"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Changes to the upper layer that take more than one operation are done on a
// file with a temporary name in the same upper layer directory. One rename or
// exchange then moves the file to its final name. Thus the overlay never shows
// a file that is incomplete, and a failure before the rename or exchange
// leaves the overlay unchanged.
//
// The filesystem records the temporary names that it uses in
// filesystem.tempNames. Files with these names on the upper layer are not
// visible in the overlay. Other files are visible, whatever their names.

// tempNamePrefix is the prefix of temporary file names on the upper layer.
const tempNamePrefix = ".gvisor-overlay-tmp-"

// tempNameRandomBytes is the number of random bytes in a temporary file name.
const tempNameRandomBytes = 16

// maxTempNameAttempts is the maximum number of names that createTemp tries.
const maxTempNameAttempts = 4

// maxTempDirDepth is the maximum depth of directories with temporary names
// that removeUpperDir removes.
const maxTempDirDepth = 8

// tempNameLen is the length of a temporary file name.
const tempNameLen = len(tempNamePrefix) + 2*tempNameRandomBytes

// isTempName returns true if name is a temporary file name that fs uses.
func (fs *filesystem) isTempName(name string) bool {
	return len(name) == tempNameLen && name[:len(tempNamePrefix)] == tempNamePrefix && fs.isRecordedTempName(name)
}

// isRecordedTempName returns true if fs.tempNames contains name.
func (fs *filesystem) isRecordedTempName(name string) bool {
	fs.tempNamesMu.Lock()
	defer fs.tempNamesMu.Unlock()
	_, ok := fs.tempNames[name]
	return ok
}

// newTempName returns a new temporary file name, and records it in
// fs.tempNames. The name is random, so that a process that can write to the
// upper layer cannot use the name before the overlay does.
func (fs *filesystem) newTempName() (string, error) {
	var b [tempNameRandomBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	var buf [tempNameLen]byte
	copy(buf[:], tempNamePrefix)
	hex.Encode(buf[len(tempNamePrefix):], b[:])
	name := string(buf[:])
	fs.tempNamesMu.Lock()
	defer fs.tempNamesMu.Unlock()
	if fs.tempNames == nil {
		fs.tempNames = make(map[string]struct{})
	}
	fs.tempNames[name] = struct{}{}
	return name, nil
}

// forgetTemp removes name from fs.tempNames. Call forgetTemp after the file
// with the temporary name name is renamed to another name or removed.
func (fs *filesystem) forgetTemp(name string) {
	fs.tempNamesMu.Lock()
	defer fs.tempNamesMu.Unlock()
	delete(fs.tempNames, name)
}

// layerChildPop returns a PathOperation for name in the layer directory dir.
func layerChildPop(dir vfs.VirtualDentry, name string) vfs.PathOperation {
	return vfs.PathOperation{
		Root:  dir,
		Start: dir,
		Path:  fspath.Parse(name),
	}
}

// createTemp calls create to make a file with a new temporary name in the
// upper layer directory dir, and returns the name.
func (fs *filesystem) createTemp(dir vfs.VirtualDentry, create func(pop vfs.PathOperation) error) (string, error) {
	for i := 0; ; i++ {
		name, err := fs.newTempName()
		if err != nil {
			return "", err
		}
		err = create(layerChildPop(dir, name))
		if err == nil {
			return name, nil
		}
		fs.forgetTemp(name)
		if !linuxerr.Equals(linuxerr.EEXIST, err) || i+1 == maxTempNameAttempts {
			return "", err
		}
	}
}

// createTempWhiteout makes a whiteout with a new temporary name in the upper
// layer directory dir, and returns the name.
func (fs *filesystem) createTempWhiteout(ctx context.Context, dir vfs.VirtualDentry) (string, error) {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	return fs.createTemp(dir, func(pop vfs.PathOperation) error {
		return CreateWhiteout(ctx, vfsObj, fs.creds, &pop)
	})
}

// renameFromTemp renames the file with the temporary name tmpName in the
// upper layer directory dir to name in dir.
func (fs *filesystem) renameFromTemp(ctx context.Context, dir vfs.VirtualDentry, tmpName, name string) error {
	if err := fs.renameUpper(ctx, dir, tmpName, dir, name, 0); err != nil {
		return err
	}
	fs.forgetTemp(tmpName)
	return nil
}

// exchangeUpper exchanges oldName in the upper layer directory oldDir and
// newName in the upper layer directory newDir. If the upper layer does not
// support RENAME_EXCHANGE, exchangeUpper exchanges the files with three
// renames. If exchangeUpper returns an error, the upper layer is unchanged.
func (fs *filesystem) exchangeUpper(ctx context.Context, oldDir vfs.VirtualDentry, oldName string, newDir vfs.VirtualDentry, newName string) error {
	err := fs.renameUpper(ctx, oldDir, oldName, newDir, newName, linux.RENAME_EXCHANGE)
	if !linuxerr.Equals(linuxerr.EINVAL, err) {
		return err
	}
	// Move the file at newName to a temporary name. Do not use
	// RENAME_NOREPLACE, which the upper layer may also not support. No other
	// file has the new temporary name, because the name is random.
	vfsObj := fs.vfsfs.VirtualFilesystem()
	tmpName, err := fs.createTemp(newDir, func(pop vfs.PathOperation) error {
		src := layerChildPop(newDir, newName)
		return vfsObj.RenameAt(ctx, fs.creds, &src, &pop, &vfs.RenameOptions{})
	})
	if err != nil {
		return err
	}
	if err := fs.renameUpper(ctx, oldDir, oldName, newDir, newName, 0); err != nil {
		if undoErr := fs.renameFromTemp(ctx, newDir, tmpName, newName); undoErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to undo rename after exchange failure: %v", undoErr))
		}
		return err
	}
	if err := fs.renameUpper(ctx, newDir, tmpName, oldDir, oldName, 0); err != nil {
		undoErr := fs.renameUpper(ctx, newDir, newName, oldDir, oldName, 0)
		if undoErr == nil {
			undoErr = fs.renameFromTemp(ctx, newDir, tmpName, newName)
		}
		if undoErr != nil {
			panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to undo renames after exchange failure: %v", undoErr))
		}
		return err
	}
	fs.forgetTemp(tmpName)
	return nil
}

// tempRemoved handles the result err of a removal of the file with the
// temporary name name from the upper layer. If the removal fails, the file
// stays on the upper layer, where it is not visible in the overlay.
func (fs *filesystem) tempRemoved(name string, err error) {
	if err == nil || linuxerr.Equals(linuxerr.ENOENT, err) {
		fs.forgetTemp(name)
		return
	}
	tempRemoveLogger.Warningf("overlay: failed to remove temporary file %q from the upper layer: %v", name, err)
}

// tempRemoveLogger logs failures to remove files with temporary names. A
// process that changes the upper layer directly can cause many such failures.
var tempRemoveLogger = log.BasicRateLimitedLogger(time.Minute)

// unlinkTemp removes the non-directory file name, which has a temporary name,
// from the upper layer directory dir.
func (fs *filesystem) unlinkTemp(ctx context.Context, dir vfs.VirtualDentry, name string) {
	pop := layerChildPop(dir, name)
	fs.tempRemoved(name, fs.vfsfs.VirtualFilesystem().UnlinkAt(ctx, fs.creds, &pop))
}

// removeTempDir removes the directory name, which has a temporary name, from
// the upper layer directory parent. dir and whiteouts are as for
// removeUpperDir.
func (fs *filesystem) removeTempDir(ctx context.Context, parent vfs.VirtualDentry, name string, dir vfs.VirtualDentry, whiteouts map[string]bool) {
	fs.tempRemoved(name, fs.removeUpperDir(ctx, parent, name, dir, whiteouts))
}

// removeUpperFile removes the file name from the private upper layer
// directory dir. isDir is true if the file is a directory, which is empty.
// removeUpperFile panics if it cannot remove the file, because the file hides
// the lower layer file.
func (fs *filesystem) removeUpperFile(ctx context.Context, dir vfs.VirtualDentry, name string, isDir bool) {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	pop := layerChildPop(dir, name)
	var err error
	if isDir {
		err = vfsObj.RmdirAt(ctx, fs.creds, &pop)
	} else {
		err = vfsObj.UnlinkAt(ctx, fs.creds, &pop)
	}
	if err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
		panic(fmt.Sprintf("unrecoverable overlayfs inconsistency: failed to remove upper layer file %q: %v", name, err))
	}
}

// removeTemp removes the file name, which has a temporary name, from the upper
// layer directory dir. If the file is a directory, removeTemp also removes the
// whiteouts and files with temporary names in it.
func (fs *filesystem) removeTemp(ctx context.Context, dir vfs.VirtualDentry, name string) {
	fs.removeTempDepth(ctx, dir, name, 0)
}

// removeTempDepth is removeTemp for a file at the depth depth of directories
// with temporary names.
func (fs *filesystem) removeTempDepth(ctx context.Context, dir vfs.VirtualDentry, name string, depth int) {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	pop := layerChildPop(dir, name)
	stat, err := vfsObj.StatAt(ctx, fs.creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err == nil && stat.Mode&linux.S_IFMT == linux.S_IFDIR {
		err = fs.removeUpperDirDepth(ctx, dir, name, vfs.VirtualDentry{}, nil, depth)
	} else if err == nil {
		err = vfsObj.UnlinkAt(ctx, fs.creds, &pop)
	}
	fs.tempRemoved(name, err)
}

// removeUpperDir removes the directory name from the upper layer directory
// parent. dir is the directory, or an empty VirtualDentry. whiteouts are the
// whiteouts in the directory, as collectWhiteoutsForRmdirLocked returns them,
// or nil. removeUpperDir also removes whiteouts and files with temporary names
// that whiteouts does not contain. If the directory contains other files,
// removeUpperDir fails with ENOTEMPTY.
func (fs *filesystem) removeUpperDir(ctx context.Context, parent vfs.VirtualDentry, name string, dir vfs.VirtualDentry, whiteouts map[string]bool) error {
	return fs.removeUpperDirDepth(ctx, parent, name, dir, whiteouts, 0)
}

// removeUpperDirDepth is removeUpperDir for a directory at the depth depth of
// directories with temporary names.
func (fs *filesystem) removeUpperDirDepth(ctx context.Context, parent vfs.VirtualDentry, name string, dir vfs.VirtualDentry, whiteouts map[string]bool, depth int) error {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	pop := layerChildPop(parent, name)
	if len(whiteouts) != 0 {
		if !dir.Ok() {
			var err error
			dir, err = vfsObj.GetDentryAt(ctx, fs.creds, &pop, &vfs.GetDentryOptions{CheckSearchable: true})
			if err != nil {
				return err
			}
			defer dir.DecRef(ctx)
		}
		for whiteout, isUpper := range whiteouts {
			if !isUpper {
				continue
			}
			childPop := layerChildPop(dir, whiteout)
			if err := vfsObj.UnlinkAt(ctx, fs.creds, &childPop); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
				return err
			}
		}
	}
	err := vfsObj.RmdirAt(ctx, fs.creds, &pop)
	if !linuxerr.Equals(linuxerr.ENOTEMPTY, err) || depth == maxTempDirDepth {
		return err
	}
	// The directory contains files that whiteouts does not contain.
	dir, err = vfsObj.GetDentryAt(ctx, fs.creds, &pop, &vfs.GetDentryOptions{CheckSearchable: true})
	if err != nil {
		return err
	}
	defer dir.DecRef(ctx)
	fd, err := vfsObj.OpenAt(ctx, fs.creds, &vfs.PathOperation{Root: dir, Start: dir}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		return err
	}
	var names, tmpNames []string
	err = fd.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
		switch {
		case dirent.Name == "." || dirent.Name == "..":
		case fs.isTempName(dirent.Name):
			tmpNames = append(tmpNames, dirent.Name)
		case dirent.Type == linux.DT_CHR:
			names = append(names, dirent.Name)
		}
		return nil
	}))
	fd.DecRef(ctx)
	if err != nil {
		return err
	}
	for _, child := range tmpNames {
		fs.removeTempDepth(ctx, dir, child, depth+1)
	}
	for _, child := range names {
		childPop := layerChildPop(dir, child)
		stat, err := vfsObj.StatAt(ctx, fs.creds, &childPop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if err != nil {
			return err
		}
		if !isWhiteout(&stat) {
			// Leave the file. RmdirAt below fails with ENOTEMPTY.
			continue
		}
		if err := vfsObj.UnlinkAt(ctx, fs.creds, &childPop); err != nil {
			return err
		}
	}
	return vfsObj.RmdirAt(ctx, fs.creds, &pop)
}

// renameUpper renames oldName in the upper layer directory oldDir to newName in
// the upper layer directory newDir. flags are RenameAt flags (linux.RENAME_*).
func (fs *filesystem) renameUpper(ctx context.Context, oldDir vfs.VirtualDentry, oldName string, newDir vfs.VirtualDentry, newName string, flags uint32) error {
	oldPop := layerChildPop(oldDir, oldName)
	newPop := layerChildPop(newDir, newName)
	return fs.vfsfs.VirtualFilesystem().RenameAt(ctx, fs.creds, &oldPop, &newPop, &vfs.RenameOptions{
		Flags: flags,
	})
}

// replaceWithWhiteout replaces the non-directory file name in the upper layer
// directory dir with a whiteout, in one rename. If replaceWithWhiteout returns
// an error, the upper layer is unchanged.
func (fs *filesystem) replaceWithWhiteout(ctx context.Context, dir vfs.VirtualDentry, name string) error {
	tmpName, err := fs.createTempWhiteout(ctx, dir)
	if err != nil {
		return err
	}
	if err := fs.renameFromTemp(ctx, dir, tmpName, name); err != nil {
		fs.unlinkTemp(ctx, dir, tmpName)
		return err
	}
	return nil
}

// createOverWhiteout calls create to make a file at name in the upper layer
// directory dir, where there is a whiteout. create makes the file at another
// name, and createOverWhiteout then moves it over the whiteout, in one rename
// or exchange. If createOverWhiteout returns an error, the upper layer is
// unchanged. isDir is true if create makes a directory; createOverWhiteout
// makes the directory opaque before it moves it.
func (fs *filesystem) createOverWhiteout(ctx context.Context, dir vfs.VirtualDentry, name string, isDir bool, create func(pop vfs.PathOperation) error) error {
	tmpName, err := fs.createTemp(dir, create)
	if err != nil {
		return err
	}
	if !isDir {
		if err := fs.renameFromTemp(ctx, dir, tmpName, name); err != nil {
			fs.unlinkTemp(ctx, dir, tmpName)
			return err
		}
		return nil
	}
	// There may be directories on lower layers, which the whiteout hides, that
	// the new directory must not merge with.
	tmpPop := layerChildPop(dir, tmpName)
	if err := fs.setOpaque(ctx, &tmpPop); err != nil {
		fs.removeTemp(ctx, dir, tmpName)
		// Like Linux, return EIO if the upper layer does not allow the xattr.
		return xattrError(err, linuxerr.EIO)
	}
	// A rename cannot replace a whiteout with a directory, so exchange them.
	if err := fs.exchangeUpper(ctx, dir, tmpName, dir, name); err != nil {
		fs.removeTemp(ctx, dir, tmpName)
		return err
	}
	// The whiteout is at tmpName.
	fs.unlinkTemp(ctx, dir, tmpName)
	return nil
}

// setOpaque makes the upper layer directory at pop opaque.
func (fs *filesystem) setOpaque(ctx context.Context, pop *vfs.PathOperation) error {
	return fs.vfsfs.VirtualFilesystem().SetXattrAt(ctx, fs.creds, pop, &vfs.SetXattrOptions{
		Name:  fs.xattrOpaque,
		Value: "y",
	})
}

// lowerLayersHaveChildLocked returns true if a file named name exists on a
// lower layer of parent. If lowerLayersHaveChildLocked cannot find out, it
// returns true.
//
// Preconditions:
//   - fs.renameMu must be locked.
//   - parent.dirMu must be locked.
func (fs *filesystem) lowerLayersHaveChildLocked(ctx context.Context, parent *dentry, name string) bool {
	vfsObj := fs.vfsfs.VirtualFilesystem()
	for _, lowerVD := range parent.lowerVDs {
		pop := layerChildPop(lowerVD, name)
		stat, err := vfsObj.StatAt(ctx, fs.creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
			continue
		}
		if err != nil {
			return true
		}
		// A whiteout on a lower layer hides the layers below it.
		return !isWhiteout(&stat)
	}
	return false
}
