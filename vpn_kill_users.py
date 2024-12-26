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
import sys
from argparse import ArgumentParser
import openvpn_management
import iamvpnlibrary
sys.dont_write_bytecode = True


class VPNkiller:
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
        self.vpn = openvpn_management.VPNmgmt(self.vpn_socket)

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


def main(argv):
    """
        The primary function, which does obviously trivial work.
    """
    parser = ArgumentParser(description='Args to the kill script')
    parser.add_argument('--noop', action='store_true', required=False,
                        help='Do not disconnect anyone',
                        dest='noop', default=False)
    parser.add_argument('vpn_socket', type=str,
                        help='VPN management socket to connect to.')
    args = parser.parse_args(argv)

    try:
        killer_object = VPNkiller(args.vpn_socket)
    except Exception as objerr:  # pylint: disable=broad-except
        # We can throw any number of exceptions during the create process.
        # Notably, if the VPN goes isolated and can't talk to IAM.
        # So, we deliberately catch all error types, because creating
        # the list would make this complex, for no benefit.
        print(f'Unable to create VPNkiller object: {str(objerr)}')
        sys.exit(1)

    if not killer_object.vpn_connect():
        print(f'Unable to connect to {args.vpn_socket}')
        sys.exit(1)

    users_to_disconnect = killer_object.get_users_to_disconnect()

    for _user, user_ref in users_to_disconnect.items():
        killer_object.disconnect_user(user_ref, commit=not args.noop)

    killer_object.vpn_disconnect()


if __name__ == "__main__":
    main(sys.argv[1:])  # pragma: no cover
