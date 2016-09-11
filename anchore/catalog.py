import datetime
import json
import logging
import tarfile
import docker
import os

from anchore.configuration import AnchoreConfiguration
from anchore.util import fs_util, scripting, contexts
from anchore.util.resources import ResourceCache

module_logger = logging.getLogger(__name__)


class Checker(object):
    """
    Generic checker for validating resources
    """
    PASS = 'pass'
    FAIL = 'fail'

    def __init__(self, resource):
        self._resource_to_check = resource

    def __call__(self):
        return self.check()

    def check(self):
        """
        Child classes must implement this function
        :return: dict with at least one 'status': '[PASS|FAIL]' item
        """
        raise NotImplementedError


class RepoSubscription(object):
    """
    The set of containers that the local registry will get updates for from upstream.
    """
    _logger = logging.getLogger(__name__)

    def __init__(self, path):
        self._file_path = path

        if not os.path.exists(path):
            self._logger.debug('No existing subscription data file found. Initializing new empty subscription')
            self._repos = []
            self.flush()
        else:
            self._logger.debug('Loading subscription data from backing file: %s' % self._file_path)
            with open(self._file_path) as f:
                self._repos = json.load(f)

    def flush(self):
        self._logger.debug('Flushing subscription data to backing file: %s' % self._file_path)
        try:
            with open(self._file_path, 'w') as fd:
                json.dump(self._repos, fd)
        except:
            self._logger.error('Failed to flush subscription list to file: %s' % self._file_path)
            raise

    def get(self):
        return self._repos

    def update(self, repos):
        """
        Adds repo entries to the subscription. If no tag is specified, then 'latest' is assumed and added
        :param repos:
        :return:
        """
        self._logger.debug('Adding %s to subscription list' % str(repos))
        for r in repos:
            if r not in self._repos:
                self._repos.append(r)

    def remove(self, repos):
        self._logger.debug('Removing %s from subscription list' % str(repos))
        for r in repos:
            if r in self._repos:
                self._repos.remove(r)


class AnalysisMetadataManager(object):
    """
    Syncs metadata (analysis output) from the hosted service. Requires the AWS CLI installed and operational
    to do the rsync-like operations
    """
    _logger = logging.getLogger(__name__)

    engine_file = 'engine.json'
    image_list_filename = 'analysis_mapping.json'

    def __init__(self, remote_sync_url, sync_dir, resource_cache, image_list_filename=None, engine_filename=None):
        self._logger.debug('Initializing analysis metadata sync manager')
        assert remote_sync_url is not None
        assert sync_dir is not None
        assert resource_cache is not None

        if engine_filename is not None:
            self.engine_file = engine_filename

        if image_list_filename is not None:
            self.image_list_file = os.path.join(self.sync_dir, image_list_filename)

        self.sync_dir = sync_dir
        self.remote_sync_url = remote_sync_url

        self._images_processed = self._load_processed_map()
        self.engine_repos, self.engine_tags = self._load_engine_repos()
        self.resource_cache = resource_cache

    def _load_processed_map(self):
        try:
            self._logger.debug('Loading list of processed images from %s' % self.image_list_file)
            if os.path.exists(self.image_list_file):
                with open(self.image_list_file) as fd:
                    return json.load(fd)
            else:
                return []
        except:
            self._logger.debug('No existing image list found. Using empty')
            return []

    def _load_engine_repos(self):
        engine_file = os.path.join(self.sync_dir, 'engine.json')
        try:
            if not os.path.exists(engine_file):
                return [], []

            self._logger.debug('Loading engine repos from %s' % engine_file)
            with open(engine_file) as source_list:
                output = json.load(source_list)
                return output['repos'], output['tags']
        except IOError:
            # Nothing local.
            self._logger.warn('Could not open, load, or initialize engine repos list')
            self._logger.debug('Failed to load engine repos list', exc_info=1)
            return None, None

    def has_synced(self):
        """
        Return true if there is analysis data present from the service
        :return:
        """
        # represent it by the engine repos/tags. If either is present, sync was done at some point
        return len(self.engine_repos) > 0 or len(self.engine_tags) > 0 and os.path.exists(self.image_list_file)

    def initialize(self):
        """
        Idempotently initialize the metadata system by checking local resources and setting up local resources.
        Does *NOT* perform a metadata sync.
        """
        try:
            if not os.path.exists(self.sync_dir):
                self._logger.debug('Initializing and creating/checking data dir: %s' % (self.sync_dir))
                fs_util.createpath(self.sync_dir, mode=0755, exists_ok=True)
        except Exception:
            self._logger.exception('Failed initializing analysis metadata directory')
            raise

    def fetch(self):
        """
        Pull the latest analysis metadata from the upstream service subject to local subscriptions

        :return:
        """

        # Safely call since idempotent
        self.initialize()

        self._logger.info('Syncing analysis metadata from Anchore service')
        old_processed = self._images_processed
        result = self.resource_cache.get(self.remote_sync_url)
        if self.remote_sync_url.endswith('.tar.gz'):
            # TODO adding this temporarily while new feed service is in progress
            tar = tarfile.open(result['content'])
            try:
                member = tar.getmember('engine.json')
                tar.extract(member, path=self.sync_dir)
            except:
                pass
            tar.close()

            # as opposed to this
            # tarfile.open(result['content']).extractall(path=self.sync_dir)

        self._images_processed = self._load_processed_map()

    def check(self):
        """
        Check the sync state of the local system relative to the upstream service. Indicate if changes are pending.
        :return:
        """

        result = {}
        # Check sync values
        result['sync'] = {}
        try:
            if self.resource_cache.is_stale(self.remote_sync_url):
                result['sync']['state'] = 'out-of-date'
            else:
                result['sync']['state'] = 'up-to-date'
            result['sync']['local_cache_metadata'] = self.resource_cache.lookup(self.remote_sync_url)
        except KeyError:
            result['sync']['state'] = 'not-synced'
        except:
            self._logger.exception('Error checking staleness of analysis db data.')
            result['sync']['state'] = 'unknown'

        result['local'] = {}
        result['local']['data_dir'] = self.sync_dir
        result['local']['data_dir_found'] = os.path.exists(self.sync_dir)
        result['local']['db_initialized'] = self.has_synced()

        return result

class ImageManager(object):
    """
    Manages images and syncing images with the local docker repo
    """
    _logger = logging.getLogger(__name__)
    _default_tag = 'latest'

    def __init__(self, docker_url, docker_conn_timeout):
        assert docker_url is not None
        self._docker_url = docker_url

        assert docker_conn_timeout is not None
        self._docker_conn_timeout = docker_conn_timeout


    def initialize(self):
        return True

    def fetch(self, image_list):
        """
        Pull the images from docker
        :return:
        """

        client = docker.Client(base_url=self._docker_url, timeout=self._docker_conn_timeout)
        for img in image_list:
            self._logger.info('Pulling image: %s' % str(img))
            if ':' in img and '@' not in img:
                img_comp = img.split(':')
                # Pull specific tag
                self._logger.debug('Syncing repo: ' + img + ' with tag = ' + self._default_tag)
                self._logger.debug(client.pull(repository=img_comp[0], tag=img_comp[1]))
            elif '@' in img:
                # It's a hash. Pass verbatim
                self._logger.debug('Syncing hash-identified image: ' + img)
                self._logger.debug(client.pull(repository=img))
            else:
                # It's repo, assume latest...
                # can later add full-repo support by removing the 'tag' here
                self._logger.debug('Syncing assumed "latest" tag for repo: ' + img)
                self._logger.debug(client.pull(repository=img, tag='latest'))

    def check(self):
        try:
            with docker.Client(base_url=self._docker_url, timeout=self._docker_conn_timeout) as client:
                info = client.info()
        except:
            return {'status': 'fail', 'docker_url': self._docker_url, 'detail': 'could not get info from docker at url'}

        return {'status': 'pass' if info is not None else 'fail', 'docker_url':self._docker_url }


class VulnerabilityManager(object):
    _logger = logging.getLogger(__name__)

    _output_dir = 'cve-data'

    def __init__(self, data_dir, remote_sync_url, resource_cache):
        assert remote_sync_url is not None
        assert resource_cache is not None and isinstance(resource_cache, ResourceCache)

        self._output_dir = os.path.join(data_dir, self._output_dir)

        self._remote_sync_url = remote_sync_url
        self.resource_cache = resource_cache

        self.initialize()

    def initialize(self):
        fs_util.createpath(self._output_dir, mode=0755, exists_ok=True)

    def has_data(self):
        """
        True if data exists in the output dir as proxy for a sync has been done
        :return:
        """
        return len(os.listdir(self._output_dir)) > 0

    def check(self):
        self._logger.debug('Checking vulnerabilities data upstream')
        result = {}

        # Check sync values
        result['sync'] = {}
        try:
            if self.resource_cache.is_stale(self._remote_sync_url):
                result['sync']['state'] = 'out-of-date'
            else:
                result['sync']['state'] = 'up-to-date'
            result['sync']['local_cache_metadata'] = self.resource_cache.lookup(self._remote_sync_url)
        except KeyError:
            result['sync']['state'] = 'not-synced'
        except:
            self._logger.exception('Error checking staleness of vulnerability data.')
            result['sync']['state'] = 'unknown'

        # check local
        result['local'] = {}
        result['local']['resource_cache_location'] = self.resource_cache.path
        result['local']['output_dir'] = self._output_dir
        result['local']['output_dir_found'] = os.path.exists(self._output_dir)
        result['local']['has_data'] = self.has_data()

        return result

    def fetch(self):
        try:
            self.initialize()  # safe idempotent op
            self._logger.info('Syncing vulnerability data from Anchore service')
            response_obj = self.resource_cache.get(self._remote_sync_url)

            if response_obj is not None:
                # Untar
                self._logger.debug('Extracting tarball contents to into %s' % self._output_dir)
                try:
                    with tarfile.open(response_obj['content']) as tarball:
                        tarball.extractall(path=self._output_dir)
                except:
                    self._logger.error('Failed to extract tarball contents.')
                    raise

        except Exception, e:
            self._logger.error('Failed to download vulnerability data: %s' % e.message)
            raise e


class UserScriptsHandler:
    def __init__(self, path):
        self.script_executor = scripting.ScriptSetExecutor(path=path)

    def execute(self):
        return self.script_executor.execute(capture_output=True, fail_fast=False)


class AnchoreCatalog(object):
    """
    Main anchore manager for the local host
    """

    _logger = logging.getLogger(__name__)
    _config_section = 'manager'
    _input_module_path = 'inputs'
    _output_module_path = 'outputs'
    _subscription_filename = 'subscription.json'
    _resource_cache_name = 'resource_cache'

    def __init__(self, config=None):
        if config is not None:
            if not isinstance(config, AnchoreConfiguration):
                raise TypeError('config parameter must be a RegistryConfiguration instance')
            else:
                self._config = config
                self._load()
        else:
            self._config = None
            self.metadata = None
            self.vulnerabilities = None
            self.images = None
            self.subscription = None

        self.inputs = UserScriptsHandler(path='/'.join([self._config['scripts_dir'], self._input_module_path]))
        self.outputs = UserScriptsHandler(path='/'.join([self._config['scripts_dir'], self._output_module_path]))

    def _load(self):
        resource_cache_dir = os.path.join(self._config['anchore_data_dir'], self._resource_cache_name)
        self.resource_cache = ResourceCache(path=resource_cache_dir,
                                            progress_bars=('quiet' not in self._config.cliargs or not self._config.cliargs['quiet']))

        self.metadata = AnalysisMetadataManager(remote_sync_url=self._config['analysis']['url'],
                                                sync_dir=self._config['image_data_store'],
                                                resource_cache=self.resource_cache)

        self.vulnerabilities = VulnerabilityManager(data_dir=self._config['anchore_data_dir'],
                                                    remote_sync_url=self._config['vulnerabilities']['url'],
                                                    resource_cache=self.resource_cache)

        self.images = ImageManager(docker_url=self._config['images']['docker_conn'], docker_conn_timeout=self._config['docker_conn_timeout'])

        self.subscription = RepoSubscription(path=os.path.join(self._config['anchore_data_dir'], self._subscription_filename))

    def has_db(self):
        """
        Has the system been initialized and the sync run at least once.
        :return: true if sync has been run (however old)
        """

        # The analysis data is the critical one to check
        return self.metadata.has_synced()

    def initialize(self, configuration=None):
        if self._config is None and (configuration is None or not isinstance(configuration, AnchoreConfiguration)):
            raise ValueError('configuration cannot be None or non-RegistryConfiguration'
                             ' if this instance does not already have a config')

        if self._config is None:
            self._config = configuration
            self._load()

        self._logger.info('Creating new anchore registry')
        self._logger.info('Initializing Metadata')
        self.metadata.initialize()
        self._logger.info('Initializing Images')
        self.images.initialize()
        self._logger.info('Initializing Vulnerabilities')
        self.vulnerabilities.initialize()

    def clean(self):
        # delete_git_repo(path=repo_path(registry_home))
        # delete_docker_registry(DEFAULT_REPO_CONTAINER_NAME)
        self._logger.info('Cleaning registry.')

    def configuration(self):
        return self._config

    def check_status(self):
        """
        Returns a dict with status output for each dependency

        :return:
        """
        analysis_status = self.metadata.check()
        image_status = self.images.check()
        vulnerabilities_status = self.vulnerabilities.check()
        # docker_registry_status = check_docker_registry(registry_home)
        status = {'Analysis Metadata': analysis_status, 'Vulnerabilities Data': vulnerabilities_status,
                  'Images': image_status}
        return status

    def pull(self):
        """
        Synchronizes the local vulnerability db with the live version upstream
        :return:
        """

        self.metadata.fetch()

        self.vulnerabilities.fetch()

        self.images.fetch(self.subscription.get())

        return True

    def subscribe(self, repo_list):
        """
        Add the given repos/tags to the subscription list after validation checks.
        If repos/tags are not available for subscription then a ValueError is raised
        :param repo_list:
        :return:
        """

        tagged_list = self._add_implicit_tags(repo_list)
        invalid = self._filter_unavailable(tagged_list)
        if invalid is None or len(invalid) == 0:
            self.subscription.update(repos=tagged_list)
            self.subscription.flush()
        else:
            raise ValueError('Containers not available to subscribe to: %s' % str(invalid))

    @staticmethod
    def _add_implicit_tags(img_list, default='latest'):
        return [ x + ':' + default if ':' not in x and '@' not in x else x for x in img_list ]


    def unsubscribe(self, repo_list):
        tagged_list = self._add_implicit_tags(repo_list)
        self.subscription.remove(repos=tagged_list)
        self.subscription.flush()

    def _filter_unavailable(self, repos):
        """
        Filter the given list and return a new list of repos that are not valid. Return [] if none
        :param containers:
        :return:
        """
        self._logger.debug('Checking engine images list source for valid subscription values: %s'
                           % str(self.metadata.engine_tags))
        tag_set = set(self.metadata.engine_tags)
        candidate_set = set(repos)

        return list(candidate_set.difference(tag_set))

    @staticmethod
    def backup(anchore_config, destdir='/tmp'):
        if not isinstance(anchore_config, AnchoreConfiguration):
            raise TypeError('anchore_config must be an instance of AnchoreConfiguration')

        dateval = datetime.datetime.now().isoformat('-')
        backupfile = os.path.join(destdir, 'anchore-backup-{0}.tar.gz'.format(dateval))

        data_dir = anchore_config['anchore_data_dir']
        image_dir = anchore_config['image_data_store']

        module_logger.info('Backing up anchore to: %s' % backupfile)
        # Just tar up the whole thing
        with tarfile.TarFile.open(name=backupfile, mode='w:gz') as tf:
            tf.add(data_dir)
            if not data_dir in image_dir:
                # It's outside the regular data dir tree, so explicitly include
                tf.add(image_dir)
            if not data_dir in anchore_config.config_dir:
                tf.add(anchore_config.config_dir)

        return backupfile

    @staticmethod
    def restore(dest_root, backup_file):
        """
        Restore saved anchore backup
        :param dest_root: string path to root dir to restore. Will install files there relative to original install dirs
        :param backup_file: a file obj or string-path to the backup file
        :return:
        """
        if not os.path.exists(dest_root):
            raise StandardError('Destination root dir does not exist')

        if isinstance(backup_file, str) and not os.path.exists(backup_file):
            raise StandardError('Backup file %s not found' % backup_file)

        if isinstance(backup_file, str):
            module_logger.info('Restoring anchore from file %s to path: %s' % (backup_file, dest_root))
            with tarfile.TarFile.open(backup_file, mode='r:gz') as tf:
                tf.extractall(path=dest_root)

        else:
            module_logger.info('Restoring anchore from file %s to path: %s' % (backup_file.name, dest_root))
            with tarfile.TarFile.open(fileobj=backup_file, mode='r:gz') as tf:
                tf.extractall(path=dest_root)

        return dest_root
