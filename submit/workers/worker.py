#!/usr/bin/env python
import errno
import json
import os
import shlex
import shutil
import select
import signal
import socket
import sys
import tempfile
import time
import traceback
from datetime import datetime
from subprocess import Popen, PIPE, STDOUT


SRC_PATH = 'src'
INPUT_PATH = 'inputs'
RESULTS_PATH = 'results'
EXECUTION_FILES_PATH = 'execution_files'

MAX_FILE_SIZE = 81920
TIME_LIMIT = 8

# Prepare Child Environemtn to disable CCACHE
CHILD_ENV = os.environ.copy()
CHILD_ENV.update(CCACHE_DISABLE='1')


def log_msg(msg):
    print('{} {} TIME_LIMIT={}'.format(datetime.now(), msg, TIME_LIMIT))


class TimeoutAlarm(Exception):
    pass


def alarm_handler(_, _a):
    raise TimeoutAlarm


class Worker(object):
    @staticmethod
    def execute(command, stderr=None, stdin=None, stdout=None, files=None,
                save=None, log=None):
        if not stderr:
            stderr = open('/dev/null', 'w')
        if not stdout:
            stdout = open('/dev/null', 'w')

        # Create temporary directory and copy execution files
        tmp_dir = tempfile.mkdtemp()
        for filename in os.listdir(EXECUTION_FILES_PATH):
            shutil.copy(os.path.join(EXECUTION_FILES_PATH, filename),
                        os.path.join(tmp_dir, filename))

        args = shlex.split(command)
        # allow some programs
        executable = None
        if args[0] not in ('bash', 'head', 'python', 'python2', 'python3',
                           'sh', 'spim', 'tail', 'valgrind'):
            executable = os.path.normpath(os.path.join(os.getcwd(), SRC_PATH,
                                                       args[0]))
            if not os.path.isfile(executable):
                raise NonexistentExecutable()
        else:
            # Need to copy the script(s) if they are listed on the command line
            for arg in args:
                src = os.path.join(SRC_PATH, arg)
                if os.path.isfile(src):
                    shutil.copy(src, os.path.join(tmp_dir, arg))

        # Hacks to give more time to some scripts:
        time_limit = TIME_LIMIT

        if args[0] in ('valgrind',):
            time_limit *= 2
        elif args[0]=='./kos':
            time_limit = 60
        elif len(args) > 2 and args[1] == 'turtle_capture.sh':
            time_limit *= 4  # How can we run this faster?

        if (log):
            log.write('worker.execute: {date} args[0]={args0} time_limit={time_limit}\n'
                     .format(date=datetime.now(), args0=args[0], time_limit=time_limit))

        # Run command with a timelimit
        # TODO: Do we only get partial output with stdout?
        try:
            poll = select.epoll()
            main_pipe = Popen(args, stdin=stdin, stdout=PIPE, stderr=stderr,
                              cwd=tmp_dir, preexec_fn=os.setsid,
                              executable=executable, env=CHILD_ENV)
            poll.register(main_pipe.stdout, select.EPOLLIN | select.EPOLLHUP)
            do_poll = True
            start = time.time()
            while do_poll:
                remaining_time = start + time_limit - time.time()
                if remaining_time <= 0:
                    if main_pipe.poll() is None:  # Ensure it's still running
                        # Kill the entire process group
                        os.killpg(main_pipe.pid, signal.SIGKILL)
                        raise TimeoutException()
                for file_descriptor, event in poll.poll(remaining_time):
                    stdout.write(os.read(file_descriptor, 8192))
                    if event == select.POLLHUP:
                        poll.unregister(file_descriptor)
                        do_poll = False

            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(time_limit)
            try:
                main_status = main_pipe.wait()
                signal.alarm(0)
            except TimeoutAlarm:
                os.killpg(main_pipe.pid, signal.SIGKILL)
                raise TimeoutException()
            if main_status < 0:
                raise SignalException(-1 * main_status)
            return main_status
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise NonexistentExecutable()
            else:
                raise
        finally:
            if save:  # Attempt to copy files requiring saving
                src = os.path.join(tmp_dir, save[0])
                if os.path.isfile(src):
                    shutil.copy(src, save[1])
            shutil.rmtree(tmp_dir)

    def __init__(self, log):
        self.log = log
        # Load testable information
        os.chdir('working')
        with open('data.json') as fp:
            self.data = json.load(fp)

    def run(self):

        self.log.write('worker.run: {date} {key} executable={executable}\n'
                     .format(date=datetime.now(), key=self.data['key'], executable=self.data['executable']))

        # Build and run tests
        os.mkdir(RESULTS_PATH)
        result = {}
        try:
            if self.data['make_target']:
                result['make'] = self.make_project(self.data['executable'],
                                                   self.data['make_target'])
            self.run_tests(self.data['test_cases'])
            result['status'] = 'success'
        except (MakeFailed, NonexistentExecutable) as exc:
            # Truncate and replace invalid ascii characters
            result['make'] = exc.message[:MAX_FILE_SIZE].decode(
                'ascii', 'replace')
            result['status'] = 'make_failed' if isinstance(exc, MakeFailed) \
                else 'nonexistent_executable'
        # Save results
        with open(os.path.join(RESULTS_PATH, 'testable'), 'w') as fp:
            json.dump(result, fp)

    def make_project(self, executable, target):
        """Build the project and verify the executable exists."""
        command = 'make -f ../Makefile -C {0} {1}'.format(SRC_PATH, target)
        pipe = Popen(command, shell=True, stdout=PIPE, stderr=STDOUT,
                     env=CHILD_ENV)
        output = pipe.communicate()[0]
        if pipe.returncode != 0:
            raise MakeFailed(output)
        if not os.path.isfile(os.path.join(SRC_PATH, executable)):
            raise NonexistentExecutable(output)
        return output

    def run_tests(self, test_cases):
        def execute(*args, **kwargs):
            try:
                result['extra'] = self.execute(*args, **kwargs)
                result['status'] = 'success'
            except NonexistentExecutable:
                result['status'] = 'nonexistent_executable'
            except SignalException as exc:
                result['extra'] = exc.signum
                result['status'] = 'signal'
            except TimeoutException:
                result['status'] = 'timed_out'

        results = {}
        for tc in test_cases:
            output_file = os.path.join(RESULTS_PATH, 'tc_{0}'.format(tc['id']))
            if tc['stdin']:
                stdin_file = os.path.join(INPUT_PATH, tc['stdin'])
                stdin = open(stdin_file)
            else:
                stdin = None
            result = {'extra': None}

            max_file_size = MAX_FILE_SIZE
            # Mange output file
            if tc['source'] != 'file':
                with open(output_file, 'wb') as output:
                    if tc['source'] == 'stdout':
                        stdout = output
                        stderr = None
                    else:
                        stdout = None
                        stderr = output
                    execute(tc['args'], stderr=stderr, stdin=stdin,
                            stdout=stdout, log=self.log)
            else:
                execute(tc['args'], save=(tc['output_filename'], output_file), log=self.log)
                if tc['output_filename'].endswith('.png'):
                    max_file_size = 131072  # Avoid truncating images

            if not os.path.isfile(output_file):
                # Hack on this status until we update the ENUM
                if result['status'] == 'success':
                    # Don't overwrite other statuses
                    result['status'] = 'output_limit_exceeded'
            elif os.path.getsize(output_file) > max_file_size:
                # Truncate output file size
                print('\ttruncating outputfile', os.path.getsize(output_file))
                fd = os.open(output_file, os.O_WRONLY)
                os.ftruncate(fd, max_file_size)
                os.close(fd)
                if result['status'] == 'success':
                    # Don't overwrite other statuses
                    result['status'] = 'output_limit_exceeded'
            results[tc['id']] = result
        with open(os.path.join(RESULTS_PATH, 'test_cases'), 'w') as fp:
            json.dump(results, fp)


class MakeFailed(Exception):
    """Indicate that the make process failed."""


class NonexistentExecutable(Exception):
    """Indicate that the expected binary does not exist."""


class SignalException(Exception):
    """Indicate that a process was terminated via a signal"""
    def __init__(self, signum):
        self.signum = signum


class TimeoutException(Exception):
    """Indicate that a process's execution timed out."""


def main():
    with open('worker.log', 'a') as fp:
        wp = Worker(fp)
        status = 'failed'
        start = time.time()
        try:
            wp.run()
            status = 'success'
            return 0
        except Exception:
            traceback.print_exc(file=fp)
            raise
        finally:
            fp.write('{date} {key} {machine} {status} in {delta} seconds\n'
                     .format(date=datetime.now(), key=wp.data['key'],
                             machine=socket.gethostname(),
                             status=status, delta=time.time() - start))


if __name__ == '__main__':
    sys.exit(main())
