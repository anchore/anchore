#!/usr/bin/env python
import os
import subprocess

default_output_path = '../../anchore/doc/man'


def check_help2man():
    if os.system('help2man --help') != 0:
        print 'Must have help2man installed.'
        exit(1)


def check_anchore():
    if os.system('anchore --version') != 0:
        print 'Must have anchore installed first.'
        exit(2)


def get_subcommands(command):
    result = subprocess.check_output(command + ['--help'])
    found = False
    subcommands = []
    for l in result.splitlines():
        if l.strip().startswith('Commands:'):
            found = True
            continue
        elif found:
            tokens = l.strip().split(' ')
            subcommands.append(command + [tokens[0]])

    return subcommands


def generate_manpages(command, recurse=False, version=None):
    print 'Processing command: ' + str(command)
    if not version:
        version = subprocess.check_output(command + ['--version'])

    outfile = os.path.join(default_output_path, '-'.join(command) + '.1')
    print 'Creating manpage ' + outfile + ' from command ' + str(command)

    if os.system(' '.join(command) + ' --extended-help') != 0:
        print 'Using --help instead of --extended-help'
        if os.system('help2man --version-string="' + version + '" -N "' + ' '.join(command) + '" > ' + outfile) != 0:
            print 'Failed on ' + str(command) + ' SKIPPING'
    else:
        if os.system(
            'help2man --help-option="--extended-help" --version-string="' + version + '" -N --no-discard-stderr "' + ' '.join(
            command) + '" > ' + outfile) != 0:
            print 'Failed on ' + str(command) + ' SKIPPING'

    try:
        subcommands = get_subcommands(command)
        print 'Subcommands: ' + str(subcommands)
    except:
        print 'Got error with subcommands for command: ' + str(command)
        return

    print 'Got subcommands: %s' % subcommands
    for cmd in subcommands:
        generate_manpages(cmd, recurse=True, version=version)


if __name__ == '__main__':
    check_anchore()
    check_help2man()

    print 'Building manpages from help output of anchore commands'
    generate_manpages(['anchore'], recurse=True)
    print 'Generation complete'