import os
import re
import stat
import logging
import sys

from tempfile import NamedTemporaryFile

from guestfs import GuestFS


class FileSystem:

    def __init__(self, disk_path):
        self._root = None
        self._handler = GuestFS()

        self.disk_path = disk_path

    def __enter__(self):
        self.mount()

        return self

    def __exit__(self, *_):
        self.umount()

    def __getattr__(self, attr):
        return getattr(self._handler, attr)

    @property
    def osname(self):
        return self._handler.inspect_get_type(self._root)

    @property
    def fsroot(self):
        if self.osname == 'windows':
            return '{}:\\'.format(
                self._handler.inspect_get_drive_mappings(self._root)[0][0])
        else:
            return self._handler.inspect_get_mountpoints(self._root)[0][0]

    def mount(self, readonly=True):
        self._handler.add_drive_opts(self.disk_path, readonly=True)
        self._handler.launch()

        for mountpoint, device in self._inspect_disk():
            try:
                if readonly:
                    self._handler.mount_ro(device, mountpoint)
                else:
                    self._handler.mount(device, mountpoint)
            except:
                # Cannot mount QCOW2 image
                logging.warning("Cannot mount device: " + device + " to " + mountpoint)

        #mountpoint, device = self._inspect_disk()[0]
        #if readonly:
        #    self._handler.mount_ro(device, mountpoint)
        #else:
        #    self._handler.mount(device, mountpoint)

        if self._handler.inspect_get_type(self._root) == 'windows':
            self.path = self._windows_path
        else:
            self.path = posix_path

    def _inspect_disk(self):

        roots = self._handler.inspect_os()

        if roots:
            self._root = roots[0]
            return sorted(self._handler.inspect_get_mountpoints(self._root),
                          key=lambda m: len(m[0]))
        else:
            # Cannot found OS in this disk image
            logging.error("No OS found on the given disk image.")
            sys.exit(-1)
            #raise RuntimeError("No OS found on the given disk image.")

    def umount(self):

        self._handler.close()

    def download(self, source, destination):
        """Downloads the file on the disk at source into destination."""
        self._handler.download(posix_path(source), destination)

    def ls(self, path):
        """Lists the content at the given path."""
        return self._handler.ls(posix_path(path))

    def nodes(self, path):
        path = posix_path(path)

        yield from (self.path(path, e) for e in self._handler.find(path))

    def checksum(self, path, hashtype='sha1'):
        """Returns the checksum of the given path."""
        return self._handler.checksum(hashtype, posix_path(path))

    def checksums(self, path, hashtype='sha1'):

        with NamedTemporaryFile(buffering=0) as tempfile:
            self._handler.checksums_out(hashtype, posix_path(path),
                                        tempfile.name)

            yield from ((self.path(f[1].lstrip('.')), f[0])
                        for f in (l.decode('utf8').strip().split(None, 1)
                                  for l in tempfile))

    def stat(self, path):

        return self._handler.stat(posix_path(path))

    def file(self, path):

        return self._handler.file(posix_path(path))

    def exists(self, path):
        """Returns whether the path exists."""
        return self._handler.exists(posix_path(path))

    def path(self, *segments):
        """Normalizes the path returned by guestfs in the File System format."""
        raise NotImplementedError("FileSystem needs to be mounted first")

    def _windows_path(self, *segments):
        drive = self._handler.inspect_get_drive_mappings(self._root)[0][0]

        return "%s:%s" % (drive, os.path.join(*segments).replace('/', '\\'))


def hash_filesystem(filesystem, hashtype='sha1'):
    """
    Returns a dictionary.
        {'/path/on/filesystem': 'file_hash'}
    """
    try:
        return dict(filesystem.checksums('/'))
    except RuntimeError:
        results = {}

        logging.warning("Error hashing disk %s contents, iterating over files.",
                        filesystem.disk_path)

        for path in filesystem.nodes('/'):
            try:
                regular = stat.S_ISREG(filesystem.stat(path)['mode'])
            except RuntimeError:
                continue  # unaccessible node

            if regular:
                try:
                    results[path] = filesystem.checksum(path, hashtype=hashtype)
                except RuntimeError:
                    logging.debug("Unable to hash %s.", path)

        return results


def posix_path(*segments):
    return re.sub('^[a-zA-Z]:', '', os.path.join(*segments)).replace('\\', '/')
