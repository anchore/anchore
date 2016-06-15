import os
import subprocess
import re
import logging


class ScriptSetExecutor:
    """
    A script module is a module for executing a set of user-provided scripts found in a specific directory in
    lexicographically sorted order

    """
    _logger = logging.getLogger(__name__)

    def __init__(self, path, file_prefix='', ascending=True):
        assert path is not None

        self.inputdir = path
        self.prefix = file_prefix
        self.sort_ascending = ascending

    def check(self, init_if_missing=False):
        """
        Check the path and construct if not found and init_if_missing=True
        :param init_if_missing: create the path if not found
        :return: true if exists false if not
        """

        if os.path.exists(self.inputdir):
            return True
        elif init_if_missing:
            os.makedirs(self.inputdir)
            return True

    def get_scripts(self, fullpath=False):
        """
        Get the scripts at the path in sorted order as set in the module properties
        :return: a sorted list of scripts
        """
        scripts = filter(lambda x: x.startswith(self.prefix), os.listdir(self.inputdir))
        scripts.sort(reverse=(not self.sort_ascending))
        if fullpath:
            return [os.path.join(self.inputdir, x) for x in scripts]
        else:
            return scripts

    def execute(self, capture_output=False, fail_fast=False, cmdline=None, **kwargs):
        """
        Pass in the kwargs as --<name> <value> pairs.
        :param capture_output: if True then return output of script in return dict. If False, only return code
        :param fail_fast:if True then quit execution after first non-zero return code, else execute all
        :returns list of (script, returncode, stdout) tuples in order of execution
        """

        scripts = self.get_scripts()
        scripts = [os.path.join(self.inputdir, x) for x in scripts]
        output = []

        for script in scripts:
            if not os.access(script, os.R_OK ^ os.X_OK) or re.match(".*~$", script):
                # Skip any that are not executable (e.g. README or txt files)
                continue

            self._logger.debug('Executing script: %s' % script)

            if cmdline:
                cmd = [script] + cmdline.split()
            else:
                cmd = [script]

            if capture_output:
                try:
                    output.append((' '.join(cmd), 0, subprocess.check_output(cmd, stderr=subprocess.STDOUT, **kwargs)))
                except subprocess.CalledProcessError as e:
                    output.append((' '.join(cmd), e.returncode, e.output))
            else:
                output.append((' '.join(cmd), subprocess.call(cmd, **kwargs), None))

            self._logger.debug('%s return code %d, output: %s' % output[-1])

            if fail_fast and output[-1][1]:
                break

        return output


