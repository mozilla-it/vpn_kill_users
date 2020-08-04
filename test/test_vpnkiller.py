# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributors:
# Guillaume Destuynder <gdestuynder@mozilla.com>
# Greg Cox <gcox@mozilla.com>
#
"""
   script testing script
"""
import unittest
import sys
import mock
import test.context  # pylint: disable=unused-import
import iamvpnlibrary
import openvpn_management
import vpn_kill_users
sys.path.insert(1, 'openvpn-management/test')
# Note that we're importing the fakeserver from our upstream module:
from fakeserver import FakeServer  # pylint: disable=wrong-import-position


UNIX_SOCKET_FILENAME = '/tmp/good-test-path'


class DevNull(object):  # pylint: disable=too-few-public-methods
    """
        A mock device to temporarily suppress output to stdout
    """
    def write(self, _someprinting):
        """ Perform no action when it comes time to print """
        pass


class TestVPNKill(unittest.TestCase):
    """ Class of tests """

    def setUp(self):
        """ Preparing test rig """
        self.server = FakeServer(UNIX_SOCKET_FILENAME)
        self.library = vpn_kill_users.VPNkiller(UNIX_SOCKET_FILENAME)
        self.server_thread = None

    def tearDown(self):
        """ Cleaning test rig """
        if self.server_thread is not None:
            self.server_thread.join()

    def test_00_init(self):
        """ Verify that the self object was initialized """
        self.assertIsInstance(self.library, vpn_kill_users.VPNkiller,
                              'VPN killer is not a proper object')
        self.assertIsInstance(self.library.vpn_socket, str,
                              'VPN killer vpn_socket was not a string')
        self.assertIsInstance(self.library.iam, iamvpnlibrary.IAMVPNLibrary,
                              'VPN killer iam was not an IAM library')
        self.assertIsInstance(self.library.vpn, openvpn_management.VPNmgmt,
                              'VPN killer vpn was not a VPNmgmt library')

    def test_01_badsetup(self):
        """
            This invokes a non-recorded VPNmgmt client aimed at a
            socket path that isn't there.  This is an expected traceback.
        """
        testobj = vpn_kill_users.VPNkiller('/tmp/badpath')
        self.assertFalse(testobj.vpn_connect(),
                         'Connecting to a bad path must return False')

    def test_02_goodsetup(self):
        """
            This invokes a client and verifies we can establish a connection.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_just_connects)
        self.assertTrue(self.library.vpn_connect(),
                        'Connecting to a good path must return True')
        # There's not much to test at this point because the connect
        # function eats the greeting output.  Soooo.  *shrug*
        # IMPROVEME -  test for a hung server that doesn't greet?

    def test_03_disconnect(self):
        """
            This invokes a client and disconnects
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_just_connects)
        self.library.vpn_connect()
        self.library.vpn_disconnect()
        # There's not much to test other than to know we didn't raise.

    def test_10_error_getuser(self):
        """
            If a server tosses an error condition, getusers should tell
            us 'no users connected' as opposed to raising.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_hates_you)
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertEqual(users, {},
                         'A confused server did not return an empty user list')

    def test_11_getuser_1(self):
        """
            Verify that we see the correct number of users on status1
            The users in the default reply are all fakes,
            so everyone should be kicked.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status, args=(1,))
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertIsInstance(users, dict,
                              'server version 1 did not return a user dict')
        self.assertEqual(len(users), 3,
                         'server version 1 did not find all users')

    def test_12_getuser_2(self):
        """
            Verify that we see the correct number of users on status2
            The users in the default reply are all fakes,
            so everyone should be kicked.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status, args=(2,))
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertIsInstance(users, dict,
                              'server version 2 did not return a user dict')
        self.assertEqual(len(users), 3,
                         'server version 2 did not find all users')

    def test_12_getuser_kiddie(self):
        """
            Verify that we see the correct number of users on status2
            The users in the default reply are all fakes,
            so everyone should be kicked.  Notably, we should not find
            the 4th user, who is not fully connected.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status, args=('kiddie',))
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertIsInstance(users, dict,
                              'server version 2 did not return a user dict')
        self.assertEqual(len(users), 3,
                         'server version 2 did not find all users')

    def test_13_getuser_3(self):
        """
            Verify that we see the correct number of users on status3
            The users in the default reply are all fakes,
            so everyone should be kicked.
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status, args=(3,))
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertIsInstance(users, dict,
                              'server version 3 did not return a user dict')
        self.assertEqual(len(users), 3,
                         'server version 3 did not find all users')

    def test_14_getuser_2(self):
        """
            Verify that we see the correct number of users on status2
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status, args=(2,))
        self.library.iam.user_allowed_to_vpn = lambda x: True
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        self.assertIsInstance(users, dict,
                              'server version 2 did not return a user dict')
        self.assertEqual(len(users), 0,
                         'When all users are valid, nobody is to be booted.')

    def test_21_kill_user_good(self):
        """
            Verify that a disconnection returns true
        """
        self.server_thread = self.server.run_a_thread(
            target=self.server.server_status_and_good_kill)
        self.library.vpn_connect()
        users = self.library.get_users_to_disconnect()
        with mock.patch('sys.stdout', new=DevNull()):
            killtest = self.library.disconnect_user(users.keys()[0])
        self.assertIsInstance(killtest, bool,
                              'kill return must be a bool')
        self.assertTrue(killtest,
                        'a good kill returns True')
