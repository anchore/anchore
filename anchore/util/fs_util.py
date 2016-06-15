import tarfile
import os
import errno
import hashlib
import io


class ResourceNotFoundException (BaseException):
    def __init__(self, resource, *args, **kwargs):
        super(ResourceNotFoundException, self).__init__(args,kwargs)
        self.message = 'Resource %s not found' % resource


class NoAccessException (BaseException):
    def __init__(self, resource, mode, *args, **kwargs):
        super(NoAccessException, self).__init__(args, kwargs)
        self.message = 'Resource %s does not have correct access mode %s' % (resource, str(mode))


def tarzip_data(root_dir, output_file):
    """
    Given a root directory, adds all its children to a tarball (compressed)
    :param root_dir:
    :param output_file:
    :return:
    """
    if root_dir is None:
        raise ValueError('Must be a valid directory path', root_dir)

    t = tarfile.open(output_file, 'w:gz')
    for child in os.listdir(root_dir):
        t.add(os.path.join(root_dir,child), arcname=child)
    t.close()
    return t.name


def check_path(path, mode=None):
    if path is not None and not os.path.exists(path):
        raise ResourceNotFoundException(path)
    if mode is not None and not os.access(path, mode):
        raise NoAccessException(path, mode)


def createpath(path, mode, exists_ok=True):
    """
    Create directories in the indicated path.
    :param path:
    :param mode:
    :param exists_ok:
    :return:
    """
    try:
        os.makedirs(path, mode)
    except OSError, e:
        if e.errno != errno.EEXIST or not exists_ok:
            raise e


def calc_file_md5(filepath, chunk_size=None):
    """
    Calculate a file's md5 checksum. Use the specified chunk_size for IO or the
    default 256KB

    :param filepath:
    :param chunk_size:
    :return:
    """
    if chunk_size is None:
        chunk_size = 256 * 1024
    md5sum = hashlib.md5()
    with io.open(filepath, 'r+b') as f:
        datachunk = f.read(chunk_size)
        while datachunk is not None and len(datachunk) > 0:
            md5sum.update(datachunk)
            datachunk = f.read(chunk_size)

    return md5sum.hexdigest()

