import logging
import sys

# The logging/output philosophy is
#
# stdout - Only the output requested by the user from the commands.
# stderr - Only error or fatal messages or other info as configured by the user
#
# output_verbosity behavior:
#     'quiet': Only output of the command is sent to stdout, stderr is only ERROR messages
#     'normal': quiet + status messages from anchore.console logger to stderr as well as ERRORs
#     'verbose': normal + all INFO-level log messages are sent stderr
#     'debug': verbose+ all DEBUG-level log messages are sent to stderr

# Common variables
DEBUG_FORMAT = '%(asctime)-15s %(levelname)s %(filename)s %(funcName)s %(message)s'
VERBOSE_FORMAT = '%(asctime)-15s %(levelname)s %(message)s'
NORMAL_FORMAT = '%(message)s'
ERR_FORMAT = '%(levelname)s %(message)s' # For errors only

DEBUG_LOGFILE_FORMAT = '%(asctime)-15s %(levelname)s %(filename)s %(funcName)s %(message)s'
LOGFILE_FORMAT = '%(asctime)-15s %(levelname)s %(message)s'

console_verbosity_options = {'quiet': -1,
                             'normal': 0,
                             'verbose': 5,
                             'debug': 10
                             }

class NoTracebackFormatter (logging.Formatter):
    """
    Formatter that does not ever include stacktraces for exception output.
    """

    def __init__(self, fmt=None, datefmt=None, err_fmt=None):
        super(NoTracebackFormatter, self).__init__(fmt=fmt, datefmt=datefmt)
        self._err_format = err_fmt if err_fmt is not None else fmt

    def format(self, record):
        """
        Modified from logging/__init__.py in python 2.7 lib

        Format the specified record as text.

        The record's attribute dictionary is used as the operand to a
        string formatting operation which yields the returned string.
        Before formatting the dictionary, a couple of preparatory steps
        are carried out. The message attribute of the record is computed
        using LogRecord.getMessage(). If the formatting string uses the
        time (as determined by a call to usesTime(), formatTime() is
        called to format the event time. If there is exception information,
        it is formatted using formatException() and appended to the message.
        """
        record.message = record.getMessage()
        if self.usesTime():
            record.asctime = self.formatTime(record, self.datefmt)

        if record.levelno >= logging.getLevelName('ERROR'):
            s = self._err_format % record.__dict__
        else:
            s = self._fmt % record.__dict__

        if record.exc_info:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            # Trim the trailing newline
            if s[-1:] == "\n":
                s = s[:-1]

            try:
                # Delimit with the colon
                s = s + ': ' + record.exc_text
            except UnicodeError:
                # Sometimes filenames have non-ASCII chars, which can lead
                # to errors when s is Unicode and record.exc_text is str
                # See issue 8924.
                # We also use replace for when there are multiple
                # encodings, e.g. UTF-8 for the filesystem and latin-1
                # for a script. See issue 13232.
                s = s + record.exc_text.decode(sys.getfilesystemencoding(),
                                               'replace')
            # Reset to avoid using the cache since this logger changes the exception format
            record.exc_text = None
        return s

    def formatException(self, ei):
        return '%s' % (ei[1])


class LoggerNamePrefixFilter(logging.Filter):
    """
    Filters out all non-Anchore records by logger name.
    """

    def __init__(self, name='', prefix=None, non_match_loglevel='ERROR'):
        super(LoggerNamePrefixFilter, self).__init__(name)
        self.non_match_level = non_match_loglevel
        self._prefix = prefix

    def filter(self, record):
        return record.name.startswith(self._prefix) or \
               record.levelno >= logging.getLevelName(self.non_match_level)


def init_output_formatters(output_verbosity='normal', stderr=sys.stderr, logfile=None, debug_logfile=None):
    """
    Initialize the CLI logging scheme.

    :param output_verbosity: 'quiet','normal','verbose', or 'debug' controls the output to stdout and its format
    :param stderr: stream for stderr output, default=stderr, pass a file path/string to have stderr in a file
    :return:
    """

    if output_verbosity not in console_verbosity_options:
        raise ValueError('output_verbosity must be one of: %s' % console_verbosity_options.keys())

    # Initialize debug log file, 'anchore-debug.log'. This log has stack-traces and is expected to be human read
    # and intended for developers and debugging, not an operational log.

    # Configure stderr behavior. All errors go to screen
    stderr_handler = logging.StreamHandler(stderr)

    if output_verbosity == 'quiet':
        stderr_handler.setLevel(level='ERROR')
        stderr_handler.setFormatter(NoTracebackFormatter(fmt=NORMAL_FORMAT, err_fmt=ERR_FORMAT))
        logging.root.setLevel('ERROR')  # Allow all at top level, filter specifics for each handler

    elif output_verbosity == 'normal':
        # The specific console logger
        stderr_handler.setLevel('INFO')
        stderr_formatter = NoTracebackFormatter(fmt=NORMAL_FORMAT, err_fmt=ERR_FORMAT)
        stderr_handler.setFormatter(stderr_formatter)
        stderr_handler.addFilter(LoggerNamePrefixFilter(prefix='anchore', non_match_loglevel='ERROR'))
        logging.root.setLevel('INFO')

    elif output_verbosity == 'verbose':
        stderr_handler.setLevel('INFO')
        stderr_handler.setFormatter(NoTracebackFormatter(fmt=NORMAL_FORMAT, err_fmt=ERR_FORMAT))
        logging.root.setLevel('INFO')

    elif output_verbosity == 'debug':
        stderr_handler.setLevel(level='DEBUG')
        stderr_handler.setFormatter(logging.Formatter(fmt=DEBUG_FORMAT))
        logging.root.setLevel('DEBUG')

    logging.root.addHandler(stderr_handler)

    if debug_logfile:
        debug_filehandler = logging.FileHandler(debug_logfile)
        debug_filehandler.setLevel('DEBUG')
        formatter = logging.Formatter(fmt=DEBUG_LOGFILE_FORMAT)
        debug_filehandler.setFormatter(formatter)
        logging.root.addHandler(debug_filehandler)
        logging.root.setLevel('DEBUG')

    if logfile:
        filehandler = logging.FileHandler(logfile)
        filehandler.setLevel('INFO')
        filehandler.setFormatter(NoTracebackFormatter(fmt=LOGFILE_FORMAT, err_fmt=LOGFILE_FORMAT))
        logging.root.addHandler(filehandler)


if __name__ == '__main__':
    code_debug = True
    print 'Running local tests'
    init_output_formatters('normal', stderr=sys.stderr, debug_logfile='./test_debug.log')

    log = logging.getLogger('anchore.test')
    log.debug('Some debug msg')
    log.info('Some info msg')
    log.error('Some error msg')
    try:
        raise StandardError('Some error exception')
    except:
        log.exception('caught exception')

    print 'Tests done'