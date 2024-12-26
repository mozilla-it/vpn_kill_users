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
import socket
import test.context  # pylint: disable=unused-import
import mock
from iamvpnlibrary import IAMVPNLibrary
from openvpn_management import VPNmgmt
from vpn_kill_users import VPNkiller, main
if sys.version_info.major >= 3:
    from io import StringIO  # pragma: no cover
else:
    from io import BytesIO as StringIO  # pragma: no cover


UNIX_SOCKET_FILENAME = '/tmp/good-test-path'  # nosec hardcoded_tmp_directory


class TestVPNKiller(unittest.TestCase):
    """ Class of tests """

    def setUp(self):
        """ Preparing test rig """
        self.library = VPNkiller(UNIX_SOCKET_FILENAME)

    def tearDown(self):
        """ Cleaning test rig """
        self.library.vpn_disconnect()

    def test_00_init(self):
        """ Verify that the self object was initialized """
        self.assertIsInstance(self.library, VPNkiller,
                              'VPN killer is not a proper object')
        self.assertIsInstance(self.library.vpn_socket, str,
                              'VPN killer vpn_socket was not a string')
        self.assertIsInstance(self.library.iam, IAMVPNLibrary,
                              'VPN killer iam was not an IAM library')
        self.assertIsInstance(self.library.vpn, VPNmgmt,
                              'VPN killer vpn was not a VPNmgmt library')

    def test_11_connect(self):
        """ Verify connections work """
        with mock.patch.object(self.library.vpn, 'connect', return_value=None) as mock_connect:
            retval = self.library.vpn_connect()
        self.assertTrue(retval)
        mock_connect.assert_called_once_with()
        with mock.patch.object(self.library.vpn, 'connect', side_effect=socket.error):
            retval = self.library.vpn_connect()
        self.assertFalse(retval)

    def test_12_disconnect(self):
        """ Verify disconnections work """
        with mock.patch.object(self.library.vpn, 'disconnect', return_value=None) as mock_connect:
            self.library.vpn_disconnect()
        mock_connect.assert_called_once_with()

    def test_21_getusers(self):
        """ Verify that we correctly identify users """
        # This mocking is fairly simple; we rely on our libraries being sane.
        users = {'Fred': ['Fred', '192.168.10.10'],
                 'Daphne': ['Daphne', '192.168.10.20'],
                 'Velma': ['Velma', '192.168.10.30'],
                 'Shaggy': ['Shaggy', '192.168.10.40'],
                 'Scooby': ['Scooby', '192.168.10.50'], }
        with mock.patch.object(self.library.vpn, 'getusers', return_value=users), \
                mock.patch.object(self.library.iam, 'user_allowed_to_vpn',
                                  side_effect=[True, True, True, True, True]):
            retval = self.library.get_users_to_disconnect()
        self.assertEqual(retval, {})
        with mock.patch.object(self.library.vpn, 'getusers', return_value=users), \
                mock.patch.object(self.library.iam, 'user_allowed_to_vpn',
                                  side_effect=[False, False, False, False, False]):
            retval = self.library.get_users_to_disconnect()
        self.assertEqual(retval, users)
        with mock.patch.object(self.library.vpn, 'getusers', return_value=users), \
                mock.patch.object(self.library.iam, 'user_allowed_to_vpn',
                                  side_effect=[True, True, False, True, True]):
            retval = self.library.get_users_to_disconnect()
        self.assertEqual(len(retval), 1)  # jinkies

    def test_22_disconnect_real(self):
        """ Verify that we disconnect users """
        with mock.patch.object(self.library.vpn, 'kill',
                               return_value=[True, 'bye Scrappy']) as mock_kill, \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            killtest = self.library.disconnect_user(['Scrappy', '192.168.10.60'], commit=True)
        self.assertIn('disconnecting from VPN: Scrappy / 192.168.10.60', fake_out.getvalue())
        mock_kill.assert_called_once_with('Scrappy', commit=True)
        self.assertTrue(killtest)

        with mock.patch.object(self.library.vpn, 'kill',
                               return_value=[True, 'bye Scrappy']) as mock_kill, \
                mock.patch('sys.stdout', new=StringIO()) as fake_out:
            killtest = self.library.disconnect_user(['Scrappy', '192.168.10.60'], commit=False)
        self.assertIn('disconnecting from VPN: Scrappy / 192.168.10.60', fake_out.getvalue())
        mock_kill.assert_called_once_with('Scrappy', commit=False)
        self.assertTrue(killtest)

    def test_90_main_bad_args(self):
        ''' Test the main function entry with junk arguments '''
        with self.assertRaises(SystemExit):
            with mock.patch('sys.stderr', new=StringIO()) as fake_out:
                main([])
        self.assertIn('usage: ', fake_out.getvalue())

        with self.assertRaises(SystemExit):
            with mock.patch('sys.stderr', new=StringIO()) as fake_out:
                main(['--junk'])
        self.assertIn('usage: ', fake_out.getvalue())

        with self.assertRaises(SystemExit):
            with mock.patch('sys.stderr', new=StringIO()) as fake_out:
                main(['--noop'])
        self.assertIn('usage: ', fake_out.getvalue())

    def test_91_main_bad_attempts(self):
        ''' Test the main function entry with unworkable operations '''
        # This one is "try to connect to something that's not in existence"
        with mock.patch.object(VPNkiller, '__init__', side_effect=ValueError):
            with self.assertRaises(SystemExit), \
                    mock.patch('sys.stdout', new=StringIO()) as fake_out:
                main(['1234'])
            self.assertIn('Unable to create VPNkiller object', fake_out.getvalue())

        # This one is "try to connect to something that's not a socket"
        with mock.patch('vpn_kill_users.VPNkiller') as mock_vpnkiller:
            instance = mock_vpnkiller.return_value
            instance.vpn_connect.return_value = False
            with self.assertRaises(SystemExit), \
                    mock.patch('sys.stdout', new=StringIO()) as fake_out:
                main(['/some/path'])
            instance.vpn_connect.assert_called_once()
            self.assertIn('Unable to connect to /some/path', fake_out.getvalue())

    @staticmethod
    def test_95_main_good():
        ''' Test the main function entry with good arguments '''
        # This is "we have nobody to kick"
        with mock.patch('vpn_kill_users.VPNkiller') as mock_vpnkiller:
            instance = mock_vpnkiller.return_value
            instance.vpn_connect.return_value = True
            instance.get_users_to_disconnect.return_value = {}
            instance.disconnect_user.return_value = (True, 'some message')
            instance.vpn_disconnect.return_value = None
            main(['/some/path'])
            instance.vpn_connect.assert_called_once()
            instance.get_users_to_disconnect.assert_called_once()
            instance.disconnect_user.assert_not_called()
            instance.vpn_disconnect.assert_called_once()

        # This is "we have one person to kick but we're in noop" mode
        with mock.patch('vpn_kill_users.VPNkiller') as mock_vpnkiller:
            instance = mock_vpnkiller.return_value
            instance.vpn_connect.return_value = True
            instance.get_users_to_disconnect.return_value = {'a': ['a', '10.20.30.40']}
            instance.disconnect_user.return_value = (True, 'some message')
            instance.vpn_disconnect.return_value = None
            main(['--noop', '/some/path'])
            instance.vpn_connect.assert_called_once()
            instance.get_users_to_disconnect.assert_called_once()
            instance.disconnect_user.assert_called_once_with(['a', '10.20.30.40'], commit=False)
            instance.vpn_disconnect.assert_called_once()

        # This is "we have one person to kick and we'll do it" mode
        with mock.patch('vpn_kill_users.VPNkiller') as mock_vpnkiller:
            instance = mock_vpnkiller.return_value
            instance.vpn_connect.return_value = True
            instance.get_users_to_disconnect.return_value = {'b': ['b', '20.40.60.80']}
            instance.disconnect_user.return_value = (True, 'some message')
            instance.vpn_disconnect.return_value = None
            main(['/some/path'])
            instance.vpn_connect.assert_called_once()
            instance.get_users_to_disconnect.assert_called_once()
            instance.disconnect_user.assert_called_once_with(['b', '20.40.60.80'], commit=True)
            instance.vpn_disconnect.assert_called_once()
