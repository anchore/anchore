#!/usr/bin/env python
import os
import subprocess

help2md_exec='/root/help2md/help2md'
output_dir='/root/command_reference/'

def check_help2md():
    if not os.path.exists(help2md_exec):
        print 'Must have help2md installed.'
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


def generate_markdown(command, recurse=False, version=None):
    print 'Processing command: ' + str(command)
    if not version:
        version = subprocess.check_output(command + ['--version'])

    outfile = os.path.join(output_dir, '-'.join(command) + '.md')
    print 'Creating manpage ' + outfile + ' from command ' + str(command)

    cmd = ' '.join(command)
    if os.system(cmd + ' --extended-help 2>&1 > /dev/null') != 0:
        print 'Using --help instead of --extended-help'
        cmd += ' --help'
    else:
        cmd += ' --extended-help'

    if os.system(cmd + ' | ' + help2md_exec + ' > ' + outfile) != 0:
        print 'Failed on ' + str(command) + ' SKIPPING'
    else:
        print 'Success for ' + str(command)

    try:
        subcommands = get_subcommands(command)
        print 'Subcommands: ' + str(subcommands)
    except:
        print 'Got error with subcommands for command: ' + str(command)
        return

    print 'Got subcommands: %s' % subcommands
    for cmd in subcommands:
        generate_markdown(cmd, recurse=True, version=version)


if __name__ == '__main__':
    check_anchore()
    check_help2md()

    print 'Building manpages from help output of anchore commands'
    generate_markdown(['anchore'], recurse=True)
    print 'Generation complete'
