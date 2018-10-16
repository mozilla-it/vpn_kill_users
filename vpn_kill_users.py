#!/usr/bin/env python
"""
    This script looks for people who are not allowed to be on the VPN
    and administratively kicks them off.

    "Why don't you just let reneg-sec do its thing?"

    Well, reneg-sec is usually off when you have MFA in place,
    and auth-gen-token is not 100% available when you have clients
    that are not all state-of-the-art.
"""
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
# Guillaume Destuynder <gdestuynder@mozilla.com>
# Greg Cox <gcox@mozilla.com>
#
# Note: parsing and matching are a little dirty,
#       but so is the OpenVPN management protocol.
# This works as of OpenVPN 2.4.6.
#
# Recommended openvpn server settings:
# management /var/run/openvpn-udp-stage.socket unix
# management-client-group vpnmgmt

import socket
import select
import sys
import re
from argparse import ArgumentParser
import iamvpnlibrary
sys.dont_write_bytecode = True


class VPNmgmt(object):
    """
        class vpnmgmt creates a socket to the openvpn management server
        and interacts with that socket.  This is just socket logic.
    """
    def __init__(self, socket_path):
        """
            Establish a socket for eventual use connecting to
            a server at a certain socket_path
        """
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket_path = socket_path

    def connect(self):
        """
            Connect to the server's socket and clear out the welcome
            banner that has no information of use in it.
        """
        self.sock.connect(self.socket_path)
        # openvpn management gives a welcome message on connect.
        # toss it, and go into nonblocking mode.
        self.sock.recv(1024)
        self.sock.setblocking(0)

    def disconnect(self):
        """
            Gracefully leave the connection if possible.
        """
        try:
            self._send('quit')
        except socket.error:
            pass
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def _send(self, command, stopon=None):
        """
            Since the interactions with openvpn management are mostly
            call-and-response, this is the internal call to go and do
            exactly that.  Send a command, read back from the server
            until it stops, or you hit something that you declare as
            a stopping point.  Then, return that (sometimes multiline)
            string to the caller.
        """
        self.sock.send(command+'\r\n')
        data = ''
        while True:
            # keep on reading until hitting timeout, in case the server is
            # being slow.  stopon is used to make this faster: you don't
            # need to wait for timeout if you know you already have the data.
            # Be careful that stopon doesn't match the data, though.
            rbuf, _wbuf, _ebuf = select.select([self.sock], [], [], 1)
            buf = ''
            for filedesc in rbuf:
                if filedesc == self.sock:
                    buf = self.sock.recv(1024)
                    data += buf
            if buf == '' or stopon is not None and data.find(stopon) != -1:
                break
        return data

    @staticmethod
    def _success(input_string):
        """
            Indicates if the openvpn management server reports a
            success (True) or failure (False) condition after
            we run a command.
        """
        if input_string.startswith('SUCCESS'):
            return True
        elif input_string.startswith('INFO'):
            return True
        else:
            return False

    def status(self):
        """
            Return the status as reported by the openvpn server.
            This will return status 2 (a comma delimited format)
            This is just to make parsing easier.
        """
        return self._send('status 2', 'END')

    def getusers(self):
        """
            Returns a dict of the users connected to the VPN:
            {
                username: [str username, str ipv4-client-address]
            }
        """
        data = self.status()
        users = {}
        if re.findall('^TITLE', data):
            # version 2 or 3, the first thing is a TITLE header;
            # We don't need multiline here.
            matched_lines = re.findall(
                r'^CLIENT_LIST[,\t](.+)[,\t](\d+\.\d+\.\d+\.\d+\:\d+)[,\t]',
                data, re.MULTILINE)
            # These DO need multiline, since data is a stream and we're
            # 'abusing' ^ by anchoring to newlines in the middle
        else:
            # version 1 or an error condition.
            matched_lines = re.findall(
                r',(.+),(\d+\.\d+\.\d+\.\d+\:\d+)',
                data)
        for matchset in matched_lines:
            # Pass along all the variables in u.
            # This makes "field 1" here be "field 1" later.
            users[matchset[0]] = matchset
        return users

    def kill(self, user, commit=False):
        """
            Disconnect a single user.  Does not check
            if they were there or not.
            Returns True/False depending on if the server
            reports a success or not.
        """
        if commit:
            ret = self._send('kill '+user, stopon='\r\n')
            return (self._success(ret), ret)
        else:
            # Send something useless, just to make testing
            # behave a bit more like real life.
            # Small bonus here, if we're disconnected, we will
            # get back a fail for testing.
            ret = self._send('version')
            return (self._success(ret), ret)


class VPNkiller(object):
    """
        This class is pretty much the overarching logic of this task.
        It's really only a class in order to be testable.
        Much of this is trivial in nature.
    """
    def __init__(self, vpn_socket):
        """
            Creates a binding class that knows about the IAM object
            (for user validation) and the VPN object (for connection
            checking and killing).
        """
        self.vpn_socket = vpn_socket
        self.iam = iamvpnlibrary.IAMVPNLibrary()
        self.vpn = VPNmgmt(self.vpn_socket)

    def vpn_connect(self):
        """
            This is the attempt to establish a connection to the openvpn
            management socket.  The upstream can raise; we're not going
            to catch it initially, as an error shouldn't happen, and if
            it does we want the script to blow out this early.
        """
        try:
            self.vpn.connect()
            return True
        except socket.error:
            return False

    def vpn_disconnect(self):
        """
            Invoke a disconnection from the VPN management socket.
        """
        self.vpn.disconnect()

    def get_users_to_disconnect(self):
        """
            Get a set of users who are to be disconnected from the VPN.
            This is an intentionally simple marriage of "look at the
            users on the VPN, and validate that they should still be
            allowed to use the VPN."
        """
        users_connected_to_vpn = self.vpn.getusers()
        # users_connected_to_vpn is the list of emails on the VPN.
        users_we_plan_to_disconnect = users_connected_to_vpn.copy()
        for user in users_connected_to_vpn:
            # We use 'user not in enabled users' rather than 'user in disabled
            # users' because disabled users would be a higher level ACL,
            # usually reserved for scripts running on the admin nodes.
            # But we checked for minimum-good user sets above.
            if self.iam.user_allowed_to_vpn(user):
                # A word of note here, 'user_allowed_to_vpn' is a remote
                # check, and thus, if we're disconnected from the server,
                # will not know the truth from the IAM system.  There is
                # a 'fail_open' check in the IAM library, and so we will
                # abide by that decision in decidind to kill users.
                del users_we_plan_to_disconnect[user]
        return users_we_plan_to_disconnect

    def disconnect_user(self, user_ref, commit=False):
        """
            log that we're going to disconnect someone, and then do so
        """
        user = user_ref[0]
        src_ip = user_ref[1].split(':')[0]
        msg = "disconnecting from VPN: {user} / {ip}"
        print(msg.format(user=user, ip=src_ip))
        kill_tuple = self.vpn.kill(user, commit=commit)
        return kill_tuple[0]


def main():
    """
        The primary function, which does obviously trivial work.
    """
    parser = ArgumentParser(description='Args to the kill script')
    parser.add_argument('--noop', action='store_true', required=False,
                        help='Do not disconnect anyone',
                        dest='noop', default=False)
    parser.add_argument('vpn_socket', type=str,
                        help='VPN management socket to connect to.')
    args = parser.parse_args()

    killer_object = VPNkiller(args.vpn_socket)

    if not killer_object.vpn_connect():
        print('Unable to connect to {sock}'.format(sock=args.vpn_socket))
        sys.exit(1)

    users_to_disconnect = killer_object.get_users_to_disconnect()

    for _user, user_ref in users_to_disconnect:
        killer_object.disconnect_user(user_ref, commit=not args.noop)

    killer_object.vpn_disconnect()


if __name__ == "__main__":
    main()
