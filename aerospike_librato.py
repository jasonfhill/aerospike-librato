#!/usr/bin/env python2
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Original Author Aerospike
# Original Copyright 2013 Aerospike

import argparse
import socket
import sys
import os
import time
import atexit
from signal import SIGTERM
import fcntl
import subprocess
import getpass
import librato
from vendor import citrusleaf


class Pidfile(object):
    def __init__(self, pidfile, procname):
        try:
            self.fd = os.open(pidfile, os.O_CREAT | os.O_RDWR)
        except IOError as e:
            sys.exit("Failed to open pidfile: %s" % str(e))
        self.pidfile = pidfile
        self.procname = procname
        assert not fcntl.flock(self.fd, fcntl.LOCK_EX)

    def unlock(self):
        assert not fcntl.flock(self.fd, fcntl.LOCK_UN)

    def write(self, pid):
        os.ftruncate(self.fd, 0)
        os.write(self.fd, "%d" % int(pid))
        os.fsync(self.fd)

    def kill(self):
        pid = int(os.read(self.fd, 4096))
        os.lseek(self.fd, 0, os.SEEK_SET)

        try:
            os.kill(pid, SIGTERM)
            time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                os.remove(self.pidfile)
            else:
                return str(err)

        if self.is_running():
            return "Failed to kill %d" % pid

    def is_running(self):
        contents = os.read(self.fd, 4096)
        os.lseek(self.fd, 0, os.SEEK_SET)

        if not contents:
            return False

        p = subprocess.Popen(["ps", "-o", "comm", "-p", str(int(contents))],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if stdout == "COMM\n":
            return False

        if self.procname in stdout[stdout.find("\n") + 1:]:
            return True

        return False


class Daemon:
    """
    A generic daemon class.
    Usage: subclass the Daemon class and override the run() method
    """

    def __init__(self, pidfile, logfile, stdin='/dev/null'):
        self.stdin = stdin
        self.stdout = logfile
        self.stderr = logfile
        self.pidfile = Pidfile(pidfile, "python")

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(
                "fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(
                "fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        self.pidfile.write(pid)

    def delpid(self):
        try:
            os.remove(str(self.pidfile))
        except OSError:
            pass

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        if self.pidfile.is_running():
            self.pidfile.unlock()
            sys.exit("Daemon already running.")

        # Start the daemon
        self.daemonize()
        self.pidfile.unlock()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        if not self.pidfile.is_running():
            self.pidfile.unlock()
            print("Daemon not running.", sys.stderr)
            return

        # Try killing the daemon process
        error = self.pidfile.kill()
        if error:
            self.pidfile.unlock()
            sys.exit(error)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be
        called after the process has been daemonized by start() or restart().
        """
        print("Running")

###########################################
#           end daemon.py
###########################################

####
# Usage :
# ## To send just the latency information to Graphite
# python citrusleaf_graphite.py -l 'latency:back=70;duration=60' \
#     --start -g s1 -p 2023
# ## To send just 1 namespace stats to Graphite, \
# for multiple namespaces, start accordingly
# python citrusleaf_graphite.py -n --start -g s1 -p 2023
# ## To send just the statistics information to Graphite
# python citrusleaf_graphite.py --start -g s1 -p 2023
# ## To send sets info to Graphite
# python citrusleaf_graphite.py -s --start -g s1 -p 2023
# ## To send XDR statistics to Graphite
# python citrusleaf_graphite.py -x --start -g s1 -p 2023
# ## To Stop the Daemon
# python citrusleaf_graphite.py --stop
####

parser = argparse.ArgumentParser()

parser.add_argument("-U"
                    , "--user"
                    , help="user name")

parser.add_argument("-P"
                    , "--password"
                    , nargs="?"
                    , const="prompt"
                    , help="password")

parser.add_argument("--stop"
                    , action="store_true"
                    , dest="stop"
                    , help="Stop the Daemon")

parser.add_argument("--start"
                    , action="store_true"
                    , dest="start"
                    , help="Start the Daemon")

parser.add_argument("--restart"
                    , action="store_true"
                    , dest="restart"
                    , help="Restart the Daemon")

parser.add_argument("-n"
                    , "--namespace"
                    , action="store_true"
                    , dest="namespace"
                    , help="Get all namespace statistics")

parser.add_argument("-s"
                    , "--sets"
                    , action="store_true"
                    , dest="sets"
                    , help="Gather set based statistics")

parser.add_argument("-l"
                    , "--latency"
                    , dest="latency"
                    ,
                    help="Enable latency statistics and specify query "
                         "(ie. latency:back=70;duration=60)")

parser.add_argument("-x"
                    , "--xdr"
                    , action="store_true"
                    , dest="xdr"
                    , help="Gather XDR statistics")

parser.add_argument("-i"
                    , "--info-port"
                    , dest="info_port"
                    , default=3000
                    , help="PORT for Aerospike server (default: %(default)s)")

parser.add_argument("-r"
                    , "--xdr-port"
                    , dest="xdr_port"
                    , default=3004
                    , help="PORT for XDR server(default: %(default)s)")

parser.add_argument("-b"
                    , "--base-node"
                    , dest="base_node"
                    , default="127.0.0.1"
                    ,
                    help="Base host for collecting stats "
                         "(default: %(default)s)")

parser.add_argument("-f"
                    , "--log-file"
                    , dest="log_file"
                    , default='/tmp/aerospike_librato.log'
                    , help="Logfile for aerospike_librato (default: %(default)s)")

parser.add_argument("-d"
                    , "--sindex"
                    , action="store_true"
                    , dest="sindex"
                    , help="Gather sindex based statistics")

parser.add_argument("-t",
                    "--librato-token",
                    dest="librato_token",
                    help="Librato authentication token")

parser.add_argument("-L",
                    "--librato-user",
                    dest="librato_user",
                    help="Librato authentication user")

parser.add_argument("-N",
                    "--name-tag",
                    dest="nametag",
                    help="Name sent to Librato (default: hostname)")

args = parser.parse_args()

user = None
password = None

if args.user is not None:
    user = args.User
    if args.password == "prompt":
        args.password = getpass.getpass("Enter Password:")
    password = citrusleaf.hashpassword(args.password)

if args.nametag is None:
    NAMETAG = socket.gethostname()
else:
    NAMETAG = str(args.nametag)

# Configurable parameters
LOGFILE = args.log_file

if not args.stop:
    if not args.librato_user:
        parser.print_help()
        sys.exit(2)
    if not args.librato_token:
        parser.print_help()
        sys.exit(2)

AEROSPIKE_SERVER = args.base_node
AEROSPIKE_PORT = args.info_port
AEROSPIKE_XDR_PORT = args.xdr_port
INTERVAL = 30
LIBRATO_PREFIX = "aerospike"


class LibratoDaemon(Daemon):
    @staticmethod
    def connect():
        librato_running = False
        q = None
        while librato_running is not True:
            try:
                api = librato.connect(args.librato_user, args.librato_token)
                q = api.new_queue()
                librato_running = True
            except:
                print("unable to connect to Librato server")
                sys.stdout.flush()
                time.sleep(INTERVAL)

        return q

    def run(self):
        q = self.connect()
        print("Aerospike-Librato connector started: ",
              time.asctime(time.localtime()))

        while True:
            r = citrusleaf.citrusleaf_info(AEROSPIKE_SERVER, AEROSPIKE_PORT,
                                           'statistics', user, password)

            if -1 != r:
                for string in r.split(';'):
                    if string == "":
                        continue

                    if string.count('=') > 1:
                        continue

                    name, value = string.split('=')
                    value = value.replace('false', "0")
                    value = value.replace('true', "1")
                    librato_name = "%s__statistics_%s" % (LIBRATO_PREFIX, name)
                    q.add(librato_name, value, source=NAMETAG)

            if args.sets:
                r = citrusleaf.citrusleaf_info(
                    AEROSPIKE_SERVER, AEROSPIKE_PORT, 'sets',
                    user, password)
                
                if -1 != r:
                    for string in r.split(';'):
                        if len(string) == 0:
                            continue
                        setlist = string.split(':')
                        namespace = setlist[0]
                        namespace_name = namespace.split('=')[1]
                        sets = setlist[1]
                        sets_name = sets.split('=')[1]

                        for set_tuple in setlist[2:]:

                            key, value = set_tuple.split('=')
                            librato_name = "%s__sets_%s_%s_%s" % (
                                LIBRATO_PREFIX, namespace_name, sets_name,
                                key)
                            q.add(librato_name, value, source=NAMETAG)

            if args.latency:
                if args.latency.startswith('latency:'):
                    r = citrusleaf.citrusleaf_info(AEROSPIKE_SERVER,
                                                   AEROSPIKE_PORT,
                                                   args.latency, user,
                                                   password)
                else:
                    r = citrusleaf.citrusleaf_info(AEROSPIKE_SERVER,
                                                   AEROSPIKE_PORT,
                                                   'latency:', user,
                                                   password)

                if (-1 != r) and not (r.startswith('error')):
                    latency_type = ""
                    header = []
                    for string in r.split(';'):
                        if len(string) == 0:
                            continue
                        if len(latency_type) == 0:
                            # Base case
                            latency_type, rest = string.split(':', 1)
                            header = rest.split(',')
                        else:
                            val = string.split(',')
                            for i in range(1, len(header)):
                                name = latency_type + "." + header[i]
                                name = name.replace('>', 'over_')
                                name = name.replace('ops/sec', 'ops_per_sec')
                                value = val[i]
                                librato_name = "%s__latency_%s" % (
                                    LIBRATO_PREFIX, name)
                                q.add(librato_name, value, source=NAMETAG)

                            # Reset base case
                            latency_type = ""
                            header = []

            if args.namespace:
                r = citrusleaf.citrusleaf_info(AEROSPIKE_SERVER,
                                               AEROSPIKE_PORT,
                                               'namespaces', user, password)

                if -1 != r:
                    namespaces = filter(None, r.split(';'))
                    if len(namespaces) > 0:
                        for namespace in namespaces:
                            r = citrusleaf.citrusleaf_info(
                                AEROSPIKE_SERVER, AEROSPIKE_PORT,
                                'namespace/' + namespace, user, password)

                            if -1 != r:
                                for string in r.split(';'):
                                    name, value = string.split('=')
                                    value = value.replace('false', "0")
                                    value = value.replace('true', "1")
                                    librato_name = "%s__namespace_%s_%s" % (
                                        LIBRATO_PREFIX, namespace, name)
                                    q.add(librato_name, value,
                                          source=NAMETAG)

            if args.xdr:
                r = citrusleaf.citrusleaf_info(AEROSPIKE_SERVER,
                                               AEROSPIKE_XDR_PORT,
                                               'statistics', user, password)

                if -1 != r:
                    for string in r.split(';'):
                        if string == "":
                            continue

                        if string.count('=') > 1:
                            continue

                        name, value = string.split('=')
                        value = value.replace('false', "0")
                        value = value.replace('true', "1")
                        # lines.append("%s.xdr.%s %s %s" % (
                        #     GRAPHITE_PATH_PREFIX, name, value, now))

                        librato_name = "%s__xdr_%s" % (
                                        LIBRATO_PREFIX, name)
                        print("%s: %s" % (librato_name, value))
                        q.add(librato_name, value, source=NAMETAG)

                # Logic to export SIndex Stats to Graphite
                # Since Graphite understands numbers we have used
                # substitutes as below
                #     sync_state --
                #         synced = 1 & need_sync = 0
                #     state --
                #         RW = 1 & WO = 0

            if args.sindex:
                pass
                # r = citrusleaf.citrusleaf_info(CITRUSLEAF_SERVER,
                #                                AEROSPIKE_PORT, 'sindex',
                #                                user, password)
                #
                # if -1 != r:
                #     indexes = filter(None, r)
                #     if len(indexes) > 0:
                #         lines = []
                #         for index_line in indexes.split(';'):
                #             if len(index_line) > 0:
                #                 index = dict(
                #                     item.split("=") for item in
                #                              index_line.split(":"))
                #
                #                 if index["sync_state"] == "synced":
                #                     index["sync_state"] = 1
                #                 elif index["sync_state"] == "need_sync":
                #                     index["sync_state"] = 0
                #
                #                 if index["state"] == "RW":
                #                     index["state"] = 1
                #                 elif index["state"] == "WO":
                #                     index["state"] = 0
                #
                #                 lines.append(
                #                     "%s.sindexes.%s.%s.sync_state %s %s" % (
                #                         GRAPHITE_PATH_PREFIX, index["ns"],
                #                         index["indexname"], index["sync_state"],
                #                         now))
                #                 lines.append("%s.sindexes.%s.%s.state %s %s" % (
                #                     GRAPHITE_PATH_PREFIX, index["ns"],
                #                     index["indexname"], index["state"], now))
                #
                #                 r = -1
                #                 try:
                #                     r = citrusleaf.citrusleaf_info(
                #                         CITRUSLEAF_SERVER, AEROSPIKE_PORT,
                #                         'sindex/' + index["ns"] + '/' + index[
                #                             "indexname"], user, password)
                #                 except:
                #                     pass
                #                 if -1 != r:
                #                     for string in r.split(';'):
                #                         name, value = string.split('=')
                #                         value = value.replace('false', "0")
                #                         value = value.replace('true', "1")
                #                         lines.append(
                #                             "%s.sindexes.%s.%s.%s %s %s" % (
                #                                 GRAPHITE_PATH_PREFIX,
                #                                 index["ns"],
                #                                 index["indexname"], name, value,
                #                                 now))

            try:
                q.submit()

            except:
                # Once the connection is broken, we need to reconnect
                print("ERROR: Unable to send to Librato server, "
                      "retrying connection..")
                sys.stdout.flush()
                q = self.connect()

            time.sleep(INTERVAL)


if __name__ == "__main__":
    daemon = LibratoDaemon('/tmp/as_librato.pid', LOGFILE)
    if args.start or args.stop or args.restart:
        if args.start:
            daemon.start()
        elif args.stop:
            daemon.stop()
        elif args.restart:
            daemon.restart()
        else:
            print("Unknown command")
            sys.exit(2)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(2)
