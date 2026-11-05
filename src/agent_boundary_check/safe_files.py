"""Small standard-library file helpers also embedded in the standalone probe."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat


def _redirected(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
    )


@contextmanager
def _parent_descriptor(path, *, strict_parents=True):
    path = Path(os.path.abspath(Path(path).expanduser()))
    if not strict_parents:
        path = path.parent.resolve(strict=True) / path.name
    directory = None
    try:
        if os.name == 'posix' and os.open in os.supports_dir_fd:
            flags = getattr(os, 'O_SEARCH', getattr(os, 'O_PATH', os.O_RDONLY)) | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
            directory = os.open(path.anchor, flags)
            for part in path.parts[1:-1]:
                try:
                    following = os.open(part, flags, dir_fd=directory)
                except PermissionError as exc:
                    # Parent-validation rights can differ from operation rights.
                    # Never call inability to validate a successful denial.
                    raise ValueError('directory safety validation is unavailable') from exc
                os.close(directory)
                directory = following
            yield path, directory
        else:
            # Reparse/symlink checks are best effort on platforms without dir_fd.
            for parent in reversed(path.parents):
                info = parent.lstat()
                if _redirected(info) or not stat.S_ISDIR(info.st_mode):
                    raise ValueError('refusing a redirected or non-directory parent')
            yield path, None
    finally:
        if directory is not None:
            os.close(directory)


def _leaf_open(path, directory, flags):
    if directory is not None:
        return os.open(path.name, flags, 0o600, dir_fd=directory)
    if path.exists() or path.is_symlink():
        if _redirected(path.lstat()):
            raise ValueError('refusing a redirected file')
    return os.open(path, flags, 0o600)


def read_regular_bytes(path, *, limit, strict_parents=True, prefix_only=False):
    """Never read a symlink, device, socket, FIFO or multiply linked file."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
    with _parent_descriptor(path, strict_parents=strict_parents) as (name, directory):
        fd = _leaf_open(name, directory, flags)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('input must be a singly linked regular file')
            if not prefix_only and info.st_size > limit:
                raise ValueError('input exceeds the byte limit')
            data = handle.read(limit + 1)
    if not prefix_only and len(data) > limit:
        raise ValueError('input exceeds the byte limit')
    return data


def write_new_text(path, text):
    """Create one private marker without following redirected path components."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    with _parent_descriptor(path) as (name, directory):
        fd = _leaf_open(name, directory, flags)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('marker must be a singly linked regular file')
                handle.write(text)
        except OSError as exc:
            # Creation has already succeeded. A later write/flush failure must
            # not be confused with a permission denial at the open boundary.
            raise ValueError('marker was created but its content write did not complete') from exc
