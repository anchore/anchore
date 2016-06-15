import os
import json
import datetime
import hashlib

import requests
import logging
import shutil
import subprocess

from clint.textui import progress

import fs_util
from anchore.util import RFC1123_TIME_FORMAT


class ResourceRetriever(object):
    """
    Interface for fetching remote resources

    """

    def __init__(self, resource_url):
        self.url = resource_url

    def fetch(self, output_path):
        raise NotImplementedError('Must be implemented by subclass')

    def get_metadata(self):
        raise NotImplementedError('Must be implemented by subclass')


user_agent_string = None


def get_user_agent():
    """
    Construct and informative user-agent string.
    Includes OS version and docker version info

    Not thread-safe
    :return:
    """

    global user_agent_string
    if user_agent_string is None:
        # get OS type
        try:
            sysinfo = subprocess.check_output('lsb_release -i -r -s'.split(' '))
            dockerinfo = subprocess.check_output('docker --version'.split(' '))

            user_agent_string = ' '.join([sysinfo.replace('\t','/'),
                                          dockerinfo.replace(" version ", "/").replace(", ", "/").replace(' ', '/')]).replace('\n','')
        except:
            user_agent_string = None

    return user_agent_string


class HttpResourceRetriever(ResourceRetriever):
    _logger = logging.getLogger(__name__)

    chunk_size = 1024 * 1024 # Bytes for each bar of the progress bar

    def fetch(self, output_path, last_etag=None, lastmodified=None, progress_bar=False):
        """
        :param output_path:
        :param last_etag:
        :param lastmodified:
        :param progress_bar:
        :return:
        """
        req_headers = {}
        usr_agent = get_user_agent()
        if usr_agent is not None:
            req_headers['User-Agent'] = usr_agent

        if last_etag is not None:
            req_headers['If-None-Match'] = '"' + last_etag + '"'
        if lastmodified is not None:
            req_headers['If-Modified-Since'] = lastmodified

        response = requests.get(self.url, headers=req_headers, stream=progress_bar)

        if response.status_code == 304:
            # Conditions didn't match, no content returned
            return None
        if response.status_code != 200:
            raise requests.HTTPError

        with open(output_path, 'wb') as f:
            if progress_bar:
                total_size = long(response.headers.get('content-length'))
                for chunk in progress.bar(response.iter_content(chunk_size=self.chunk_size),
                                          expected_size=(total_size / self.chunk_size) + 1):
                    if chunk:
                        f.write(chunk)
                        f.flush()
            else:
                f.write(response.content)

        headers = normalize_headers(response.headers)

        if 'etag' not in headers:
            headers['etag'] = fs_util.calc_file_md5(output_path)

        return headers

    def get_metadata(self):
        response = requests.head(self.url)
        if response.status_code != 200:
            return None
        else:
            return normalize_headers(response.headers)


def normalize_headers(headers):
    """
    Convert useful headers to a normalized type and return in a new dict

    Only processes content-type, content-length, etag, and last-modified
    :param headers:
    :return:
    """
    for (k, v) in headers.items():
        headers.pop(k)
        headers[k.lower()] = v

    result = {}
    if 'content-length' in headers:
        result['content-length'] = headers['content-length']
    elif 'contentlength' in headers:
        result['content-length'] = headers['contentlength']

    if 'content-type' in headers:
        result['content-type'] = headers['content-type']
    elif 'contenttype' in headers:
        result['content-type'] = headers['contenttype']

    if 'last-modified' in headers:
        result['last-modified'] = headers['last-modified']
    elif 'lastmodified' in headers:
        result['last-modified'] = headers['lastmodified']
    else:
        result['last-modified'] = datetime.datetime.utcnow().strftime(RFC1123_TIME_FORMAT)

    # Normalize date
    if isinstance(result['last-modified'], datetime.datetime):
        result['last-modified'] = result['last-modified'].strftime(RFC1123_TIME_FORMAT)

    if 'ETag' in headers:
        result['etag'] = headers['etag'].strip('"')
    elif 'etag' in headers:
        result['etag'] = headers['etag'].strip('"')

    return result

def get_resource_retriever(url):
    """
    Get the appropriate retriever object for the specified url based on url scheme.
    Makes assumption that HTTP urls do not require any special authorization.

    For HTTP urls: returns HTTPResourceRetriever
    For s3:// urls returns S3ResourceRetriever

    :param url: url of the resource to be retrieved
    :return: ResourceRetriever object
    """

    if url.startswith('http://') or url.startswith('https://'):
        return HttpResourceRetriever(url)
    else:
        raise ValueError('Unsupported scheme in url: %s' % url)


class ResourceCache(object):
    """
    A Resource cache backed by a local directory.
    Composed of a storage directory with content files (named by etag) and a metadata file
    that preserves HTTP headers and maps the content files to the URLs from whence they came. Handles the case of
    the same content via different URLs (common with S3, for example).
    """
    _logger = logging.getLogger(__name__)
    metadata_filename = 'cache_metadata.json'

    def __init__(self, path='/tmp', progress_bars=False):
        self.path = path
        self.progress_bars = progress_bars
        #self.progress_bars = False

        self.metadata_file = os.path.join(self.path, self.metadata_filename)
        self.metadata = {}

        if not os.path.exists(self.metadata_file):
            self._logger.debug('Initializing resource cache at %s' % self.path)
            fs_util.createpath(path=self.path, mode=0744, exists_ok=True)
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f)
        else:
            with open(self.metadata_file) as f:
                self.metadata = json.load(f)

        self._validate_cache()

    def _validate_cache(self):
        for url, entry in self.metadata.items():
            # Remove any where file is not found. Can occur due to use Ctrl-C or unexpected failure
            if not os.path.exists(entry['content']):
                self.metadata.pop(url)

    def lookup(self, url):
        """
        Like 'get', but only returns metadata if present. Will *not* download/load the cache
        :param url:
        :return:
        """
        return self.metadata[url]

    def check(self, url):
        return url in self.metadata

    def is_stale(self, url):
        self._logger.debug('Checking staleness of url %s into resource cache' % url)
        retriever = get_resource_retriever(url)

        try:
            if url in self.metadata:
                headers = retriever.get_metadata()
                if 'etag' in headers:
                    return self.metadata[url]['etag'] != headers['etag']
                elif 'lastmodified' in headers:
                    return self.metadata[url]['lastmodified'] != headers['lastmodified']

            else:
                return True
        except Exception, e:
            self._logger.debug('Error checking staleness of %s: %s' % (url, e.message))
            raise

    def get(self, url):
        """
        Lookup the given url and return an entry if found. Else return None.
        The returned entry is a dict with metadata about the content and a 'content' key with a file path value

        :param url:
        :return:
        """
        self._load(url)
        self._flush()

        return self.metadata[url]

    def is_empty(self):
        return len(self.metadata) == 0

    def clear(self):
        """
        Remove all entries from the cache and delete all data.
        :return:
        """
        for f in [x['content'] for x in self.metadata.values()]:
            os.remove(f)

        self.metadata = {}
        self._flush()

    @staticmethod
    def _hash_path(url):
        return hashlib.md5(url).hexdigest()

    def _load(self, url):
        """
        Load from remote, but check local file content to identify duplicate content. If local file is found with
        same hash then it is used with metadata from remote object to avoid fetching full content.

        :param url:
        :return:
        """
        self._logger.debug('Loading url %s into resource cache' % url)
        retriever = get_resource_retriever(url)
        content_path = os.path.join(self.path, self._hash_path(url))

        try:
            if url in self.metadata:
                headers = retriever.fetch(content_path, last_etag=self.metadata[url]['etag'], progress_bar=self.progress_bars)
                if headers is None:
                    # no update, return what is already loaded
                    self._logger.info('Cached %s is up-to-date. No data download needed' % url)
                    return self.metadata[url]
            else:
                headers = retriever.fetch(content_path, progress_bar=self.progress_bars)
                if headers is None:
                    raise Exception('Fetch of %s failed' % url)

            if 'etag' not in headers:
                # No Etag returned, so generate it
                headers['etag'] = fs_util.calc_file_md5(content_path)

            # Populate metadata from the headers
            self.metadata[url] = headers.copy()
            self.metadata[url]['content'] = content_path
            return self.metadata[url]
        except:
            self._logger.error('Failed getting resource: %s')

            # forcibly flush local entry if found
            if url in self.metadata:
                self.metadata.pop(url)
            raise
        finally:
            if url not in self.metadata:
                self._logger.debug('Cleaning up on failed load of %s' % url)
                # Cleanup on failure
                if content_path is not None and os.path.exists(content_path):
                    os.remove(content_path)

    def _flush(self):
        """
        Flush metadata to the backing file
        :return:
        """
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f)

    #def __del__(self):
        # Ensure the lock is released
        #fcntl.flock(self._metadata_fd, fcntl.LOCK_UN)
