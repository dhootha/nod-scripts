#!/bin/bash -e

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

# KNOWN_HOSTS - defaults to /etc/nod-known-hosts.asc
# KNOWN_HOSTS_URL - defaults to https://dl.farsightsecurity.com/....
# USER - the user on the rsync server
# SSH_IDENTITY - overrides the ssh identity file
# SSH_ARGS - any extra arguments to ssh
# RSYNC - path to the rsync binary

if [ -r "/etc/nod-rsync.conf" ]; then
	. /etc/nod-rsync.conf
fi

if [ -r "$HOME/.nod-rsync.conf" ]; then
	. $HOME/.nod-rsync.conf
fi

if [ -z $RSYNC_HOST ]; then
	echo "RSYNC_HOST is required" >&2
	exit 1
fi

if [ -z $REMOTE_PATH ]; then
	echo "REMOTE_PATH is required" >&2
	exit 1
fi

if [ -z $TARGET ]; then
	echo "TARGET is required" >&2
	exit 1
fi

if [ -z $RSYNC ]; then
	RSYNC=`which rsync || true`
fi
if [ -z $RSYNC ]; then
	echo "Error: Can not find rsync binary, RSYNC not set." >&2
	exit 1
fi
if [ ! -x $RSYNC ]; then
	echo "Error: $RSYNC is not executable" >&2
	exit 1
fi

if [ -z $KNOWN_HOSTS ]; then
	KNOWN_HOSTS=/etc/nod-known-hosts
fi
if [ -z $KNOWN_HOSTS_URL ]; then
	KNOWN_HOSTS_URL=https://dl.farsightsecurity.com/resources/nod/known_hosts
fi
SSH_ARGS="$SSH_ARGS -o GlobalKnownHostsFile=$KNOWN_HOSTS"

KNOWN_HOSTS_SHA=`shasum $KNOWN_HOSTS | cut -f 1 -d' '`
set -- `dig +short -t TXT known-hosts._sha1.$RSYNC_HOST`
EXPECTED_KNOWN_HOSTS_SHA=${1#\"}
KNOWN_HOSTS_VERSION=${2%\"}

if [ ! -z "$EXPECTED_KNOWN_HOSTS_SHA" -a "$KNOWN_HOSTS_SHA" != "$EXPECTED_KNOWN_HOSTS_SHA" ]; then
	if [ -z $KNOWN_HOSTS_URL ]; then
		echo "Error: KNOWN_HOSTS_URL not set and known-hosts is out of date"
		exit 1
	fi

	KNOWN_HOSTS_DIR=`dirname $KNOWN_HOSTS`
	KNOWN_HOSTS_BASE=`basename $KNOWN_HOSTS`
	KNOWN_HOSTS_TMP=`TMPDIR=$KNOWN_HOSTS_DIR mktemp .$KNOWN_HOSTS_BASE.XXXXXX`
	trap "rm -f $KNOWN_HOSTS_TMP" exit

	wget -O "$KNOWN_HOSTS_TMP" "$KNOWN_HOSTS_URL.$KNOWN_HOSTS_VERSION"

	NEW_KNOWN_HOSTS_SHA=`shasum $KNOWN_HOSTS_TMP | cut -f 1 -d' '`
	if [ $NEW_KNOWN_HOSTS_SHA -ne $EXPECTED_KNOWN_HOSTS_SHA ]; then
		echo "Warning: Checksum for new known hosts file does not match.  Not replacing."
		rm -f $KNOWN_HOSTS_TMP
	else
		mv -f $KNOWN_HOSTS_TMP $KNOWN_HOSTS
	fi

fi

if [ ! -z $SSH_IDENTITY ]; then
	SSH_ARGS="$SSH_ARGS -i $SSH_IDENTITY"
fi

if [ -z $WRAPSRV ]; then
	WRAPSRV=`which wrapsrv || true`
fi

if [ -z $WRAPSRV ]; then
	echo "Warning: wrapsrv not present, failover disabled" >&2
	if [ -z $PORT ]; then
		PORT=49222
	fi
	exec $RSYNC -a -e "ssh -p $PORT $SSH_ARGS" "$USER@$RSYNC_HOST:$REMOTE_PATH" "$TARGET"
else
	exec $WRAPSRV _rsync._tcp.$RSYNC_HOST $RSYNC -a -e "'ssh -p %p $SSH_ARGS'" "$USER@%h:$REMOTE_PATH" "$TARGET"
fi

