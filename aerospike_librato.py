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

import ConfigParser

import socket
import sys
import os
import time
import librato
from vendor import citrusleaf

config = ConfigParser.ConfigParser()

try:
    config.readfp(open('default-config.ini'))
except IOError:
    print('Unable to open configuration file (default-config.ini)')
    sys.exit(1)

config.read(['aerospike-librato.ini',
             os.path.expanduser('~/.aerospike-librato.ini')])

aerospike_authentication = config.getboolean('main', 'aerospike_authentication')
try:
    user = config.get('main', 'user', None)
    password = config.get('main', 'password')
    if password:
        password = citrusleaf.hashpassword(password)
except ConfigParser.NoOptionError:
    if aerospike_authentication:
        sys.exit("user/password required for Aerospike authentication.")
    else:
        user = None
        password = None

try:
    nametag = config.get('main', 'nametag')
except ConfigParser.NoOptionError:
    nametag = socket.gethostname()

base_node = config.get('main', 'base_node')
logfile = config.get('main', 'log_file')
aerospike_namespace = config.getboolean('main', 'aerospike_namespace')
aerospike_sets = config.getboolean('main', 'aerospike_sets')
xdr = config.getboolean('main', 'xdr')
latency = config.get('main', 'latency')
info_port = config.getint('main', 'info_port')
xdr_port = config.getint('main', 'xdr_port')
librato_token = config.get('main', 'librato_token')
librato_user = config.get('main', 'librato_user')
interval = config.getint('main', 'interval')
librato_prefix = config.get('main', 'librato_prefix')


class Monitor:
    """ Start monitoring Aerospike
    """
    @staticmethod
    def connect():
        librato_running = False
        q = None

        while librato_running is not True:
            try:
                api = librato.connect(librato_user, librato_token)
                q = api.new_queue()
                librato_running = True
            except:
                print("unable to connect to Librato server")
                sys.stdout.flush()
                time.sleep(interval)

        return q

    def __init__(self):
        q = self.connect()

        while True:
            r = citrusleaf.citrusleaf_info(base_node, info_port,
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
                    librato_name = "%s__statistics_%s" % (librato_prefix, name)
                    q.add(librato_name, value, source=nametag)

            if aerospike_sets:
                r = citrusleaf.citrusleaf_info(
                    base_node, info_port, 'sets',
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
                                librato_prefix, namespace_name, sets_name,
                                key)
                            q.add(librato_name, value, source=nametag)

            if latency:
                if latency.startswith('latency:'):
                    r = citrusleaf.citrusleaf_info(base_node, info_port,
                                                   latency, user, password)
                else:
                    r = citrusleaf.citrusleaf_info(base_node, info_port,
                                                   'latency:', user, password)

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
                                    librato_prefix, name)
                                q.add(librato_name, value, source=nametag)

                            # Reset base case
                            latency_type = ""
                            header = []

            if aerospike_namespace:
                r = citrusleaf.citrusleaf_info(base_node, info_port,
                                               'namespaces', user, password)

                if -1 != r:
                    namespaces = filter(None, r.split(';'))
                    if len(namespaces) > 0:
                        for namespace in namespaces:
                            r = citrusleaf.citrusleaf_info(
                                base_node, info_port,
                                'namespace/' + namespace, user, password)

                            if -1 != r:
                                for string in r.split(';'):
                                    name, value = string.split('=')
                                    value = value.replace('false', "0")
                                    value = value.replace('true', "1")
                                    librato_name = "%s__namespace_%s_%s" % (
                                        librato_prefix, namespace, name)
                                    q.add(librato_name, value,
                                          source=nametag)

            if xdr:
                r = citrusleaf.citrusleaf_info(base_node, xdr_port,
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
                        librato_name = "%s__xdr_%s" % (librato_prefix, name)
                        q.add(librato_name, value, source=nametag)

            try:
                q.submit()
            except:
                # Once the connection is broken, we need to reconnect
                print("ERROR: Unable to send to Librato server, "
                      "retrying connection..")
                sys.stdout.flush()
                q = self.connect()

            time.sleep(interval)


if __name__ == "__main__":
    Monitor()