#!/usr/bin/env python

# Copyright (c) 2013 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Requires the following environment variables to be set in the shell, or in
# /etc/nod-rsync.conf or $HOME/.nod-rsync.conf:

# RSYNC_HOST - the hostname or service name of the rsync server
# REMOTE_PATH - the remote path on the rsync server to synchronize
# TARGET - the local path that rsync writes to

# The following optional environment variables may also be set:

# KNOWN_HOSTS_URL - defaults to https://dl.farsightsecurity.com/....
# USER - the user on the rsync server
# SSH_IDENTITY - overrides the ssh identity file
# SSH_ARGS - any extra arguments to ssh
# RSYNC - path to the rsync binary

import argparse
import logging
import os
import random
import sha
import subprocess
import sys
import tempfile
import time

logger = logging.getLogger('nod-rsync')

try:
    import pwd
    default_user = pwd.getpwuid(os.getuid()).pw_name
except ImportError:
    logger.debug('pwd unavailable')
    default_user = None

class HTTPError(Exception):
    pass

try:
    import requests

    def http_get(url):
        try:
            return requests.get(url).content
        except requests.exceptions.RequestException as e:
            raise HTTPError(e)
except ImportError:
    import urllib2

    logger.warning("Python requests not available, falling back to urllib2.")
    logger.warning("SSL certificate validation not available.")

    def http_get(url):
        try:
            return urllib2.urlopen(url).read()
        except (urllib2.HTTPError, urllib2.URLError) as e:
            raise HTTPError(e)

def which(command, path=None):
    if path is None:
        path = os.environ['PATH']

    if isinstance(path, (str, bytes, unicode)):
        path = path.split(os.pathsep)

    for p in path:
        abs_fn = os.path.join(p, command)
        if os.path.isfile(abs_fn) and os.access(abs_fn, os.X_OK):
            return abs_fn

    return None

try:
    import dns.resolver

    def txt_query(query):
        try:
            return dns.resolver.query(query, 'TXT')[0].strings[0]
        except dns.resolver.NXDOMAIN as e:
            logger.error('{}: NXDOMAIN'.format(query))
            return ''
        except dns.exception.DNSException as e:
            logger.error('{}: {}'.format(query, str(e.__class__)))
            return ''
except ImportError:
    logger.info('dnspython unavailable, using dig')
    _dig_path = which('dig')

    if not _dig_path:
        raise RuntimeError("dig unavailable")

    def txt_query(query):
        dig_out = tempfile.TemporaryFile()
        dig_err = tempfile.TemporaryFile()
        try:
            subprocess.check_call([_dig_path, '+short', '-t', 'TXT', query], stdin=open('/dev/null'), stdout=dig_out, stderr=dig_err)
            dig_out.seek(0)
            return dig_out.read().strip('"\n')
        except subprocess.CalledProcessError as e:
            logger.error(str(e))
            return ''

def load_config(f, config=None):
    if config is None:
        config = dict()

    for line in f:
        line = line.strip()
        if not line:
            continue

        key, eq, val = line.partition('=')
        val = val.strip('"')
        config[key] = val

    return config

class KnownHosts:
    def __init__(self, base_url, rsync_host):
        self._temp_file = tempfile.NamedTemporaryFile()

        self._url = base_url
        self._rsync_host = rsync_host

        self.check()

    def name(self):
        return self._temp_file.name

    def check(self):
        self._temp_file.seek(0)
        sha_hash = sha.new()
        sha_hash.update(self._temp_file.read())
        digest = sha_hash.hexdigest()

        try:
            expected_digest, file_version = txt_query('known-hosts._sha1.{rsync_host}'.format(rsync_host = self._rsync_host)).split()
        except ValueError as e:
            logger.error(str(e))
            return False

        if digest != expected_digest:
            logger.info("Retrieving known hosts version {version}".format(version=file_version))
            try:
                new_data = http_get(self._url.format(sha1={expected_digest}, version=file_version))
            except HTTPError as e:
                logger.error(str(e))
                return False

            new_sha_hash = sha.new()
            new_sha_hash.update(new_data)
            new_digest = new_sha_hash.hexdigest()

            if new_digest == expected_digest:
                self._temp_file.seek(0)
                self._temp_file.write(new_data)
                self._temp_file.flush()
                return True
            else:
                logger.warning("known host digest mismatch")
                return False

        return False

def run_rsync(args, known_hosts):
    ssh_extra_args = '-o GlobalKnownHostsFile={known_hosts} -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey -o ForwardAgent=no -o ForwardX11=no -o StrictHostKeyChecking=yes'.format(known_hosts=known_hosts.name())

    rsync_out = tempfile.TemporaryFile()
    rsync_err = tempfile.TemporaryFile()

    try:
        if not args.wrapsrv_path:
            subprocess.check_call([args.rsync_path, '-a', '-e',
                'ssh -p {port} {ssh_args} {ssh_extra_args}'.format(port=args.ssh_port, ssh_args=args.ssh_args, ssh_extra_args=ssh_extra_args),
                '{user}@{rsync_host}:{remote_path}'.format(
                    user=args.user, rsync_host=args.rsync_host, remote_path=args.remote_path),
                args.target], stdin=open('/dev/null'), stdout=rsync_out, stderr=rsync_err)
        else:
            subprocess.check_call([args.wrapsrv_path, '_rsync._tcp.{}'.format(args.rsync_host),
                args.rsync_path, '-a', '-e',
                '"ssh -p %p {ssh_args} {ssh_extra_args}"'.format(ssh_args=args.ssh_args, ssh_extra_args=ssh_extra_args),
                '{user}@%h:{remote_path}'.format(
                    user=args.user, remote_path=args.remote_path),
                args.target], stdin=open('/dev/null'), stdout=rsync_out, stderr=rsync_err)
    except subprocess.CalledProcessError as e:
        logger.error(str(e))
        rsync_out.seek(0)
        stdout = rsync_out.read()
        if stdout:
            for line in stdout.rstrip().split('\n'):
                logger.error(line.rstrip())

        rsync_err.seek(0)
        stderr = rsync_err.read()
        if stderr:
            for line in stderr.rstrip().split('\n'):
                logger.error(line.rstrip())

def sync_loop(args):
    known_hosts = KnownHosts(args.known_hosts_url, args.rsync_host)

    logger.info('running rsync')
    run_rsync(args, known_hosts)

    t_sleep=random.random()*args.period
    logger.debug('sleeping for {}'.format(t_sleep))
    time.sleep(t_sleep)

    while True:
        t_start = time.time()
        known_hosts.check()

        logger.info('running rsync')
        run_rsync(args, known_hosts)

        t_elapsed = time.time() - t_start
        t_remaining = args.period - t_elapsed

        if t_remaining > 0:
            logger.debug('sleeping for {}'.format(t_remaining))
            time.sleep(t_remaining)

def main():
    parser = argparse.ArgumentParser(description='Rsync manager for Farsight NOD.')
    parser.add_argument('--daemon', '-d', action='store_true',
            help='Run as a daemon.  Requires python-daemon.')
    parser.add_argument('--verbosity', '-v', action='count',
            help='Increase output verbosity.')
    parser.add_argument('--log-file', '-l', help='Log file.')
    parser.add_argument('--pid-file', '-D', help='Pid file for daemon.')
    parser.add_argument('--rsync-host', '-H', help='Host/SRV to rsync from.')
    parser.add_argument('--remote-path', '-p', help='Remote path to rsync from.')
    parser.add_argument('--target', '-t', help='Local path to rsync to.')
    parser.add_argument('--user', '-u', help='Remote username.')
    parser.add_argument('--period', '-P', type=int, help='How often to run rsync.')
    parser.add_argument('--known-hosts-url', '-U', help='URL to fetch known hosts file from.')
    parser.add_argument('--ssh-args', '-a', help='Extra arguments passed to ssh.')
    parser.add_argument('--ssh-identity', '-i', help='ssh identity file.')
    parser.add_argument('--ssh-path', help='Path to ssh binary.')
    parser.add_argument('--ssh-port', '-s', help='TCP port to connect on via ssh.')
    parser.add_argument('--rsync-path', help='Path to rsync binary.')
    parser.add_argument('--wrapsrv-path', help='Path to wrapsrv binary.')
    args = parser.parse_args()

    config = {
            'RSYNC_HOST' : 'rsync.dns-nod.net',
            'REMOTE_PATH' : None,
            'TARGET' : None,
            'USER' : default_user,

            'DEFAULT_LOG_FILE' : os.path.expanduser('~/nod-rsync.log'),
            'LOG_FILE' : None,
            'PID_FILE' : os.path.expanduser('~/nod-rsync.pid'),

            'PERIOD' : 60,
            'KNOWN_HOSTS_URL' : 'https://dl.farsightsecurity.com/resources/nod/known_hosts.{version}',
            'SSH_ARGS' : '',
            'SSH_IDENTITY' : None,
            'SSH_PORT' : 49222,

            'SSH' : which('ssh'),
            'RSYNC' : which('rsync'),
            'WRAPSRV' : which('wrapsrv'),
            }

    for cfg_file in ('/etc/nod-rsync.conf', os.path.expanduser('~/.nod-rsync.conf')):
        if os.path.exists(cfg_file) and os.access(cfg_file, os.R_OK):
            config = load_config(open(cfg_file), config)

    for key in config:
        if key in os.environ:
            config[key] = os.environ[key]

    if args.rsync_host is None:
        args.rsync_host = config['RSYNC_HOST']
    if not args.rsync_host:
        parser.error('rsync host is not set')

    if args.remote_path is None:
        args.remote_path = config['REMOTE_PATH']
    if not args.remote_path:
        parser.error('remote path is not set')

    if args.target is None:
        args.target = config['TARGET']
    if not args.target:
        parser.error('target is not set')

    if args.user is None:
        args.user = config['USER']
    if not args.user:
        parser.error('user is not set')

    if args.period is None:
        args.period = int(config['PERIOD'])
    if args.period < 60:
        parser.error('period less than 1 minute')

    if args.known_hosts_url is None:
        args.known_hosts_url = config['KNOWN_HOSTS_URL']

    if args.ssh_args is None:
        args.ssh_args = config['SSH_ARGS']

    if args.ssh_identity is None:
        args.ssh_identity = config['SSH_IDENTITY']
    if args.ssh_identity:
        args.ssh_args += ' -i {identity}'.format(identity=args.ssh_identity)

    if args.ssh_path is None:
        args.ssh_path = config['SSH']
    if not args.ssh_path:
        parser.error('ssh not available')

    if args.ssh_port is None:
        args.ssh_port = int(config['SSH_PORT'])

    if args.rsync_path is None:
        args.rsync_path = config['RSYNC']
    if not args.rsync_path:
        parser.error('rsync not available')

    if args.wrapsrv_path is None:
        args.wrapsrv_path = config['WRAPSRV']

    if args.log_file is None:
        args.log_file = config['LOG_FILE']

    if args.pid_file is None:
        args.pid_file = config['PID_FILE']

    if args.verbosity == 0:
        logger.setLevel(logging.ERROR)
    elif args.verbosity == 1:
        logger.setLevel(logging.WARNING)
    elif args.verbosity == 2:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)

    if args.daemon:
        import daemon
        import daemon.pidlockfile

        handler = logging.FileHandler(os.path.abspath(args.log_file or config['DEFAULT_LOG_FILE']))
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)

        with daemon.DaemonContext(files_preserve=[handler.stream],
                pidfile=daemon.pidlockfile.PIDLockFile(os.path.abspath(args.pid_file))):
            sync_loop(args)
    else:
        if args.log_file:
            handler = logging.FileHandler(args.log_file)
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        else:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

        logger.addHandler(handler)

        sync_loop(args)

if __name__ == "__main__":
    main()
