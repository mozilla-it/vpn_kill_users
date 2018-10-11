#!/usr/bin/env python
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
# This test file calls protected methods on the script classes
# file, so, we tell pylint that we're cool with it globally:
# pylint: disable=protected-access

import os
import sys
import socket
import time
import threading
import textwrap

sys.dont_write_bytecode = True


class FakeServer(object):
    """ A fake unix socket server """
    # Things I send:
    initial_connect = ">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info"
    unknown_command = "ERROR: unknown command, enter 'help' for more options"
    status_1 = textwrap.dedent('''\
        OpenVPN CLIENT LIST
        Updated,Tue Sep 25 22:39:46 2018
        Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
        person3@company.com,5.6.7.8:33874,16709424,3109968,Tue Sep 25 16:32:49 2018
        person1@company.com,9.10.11.12:40743,1144713,9980107,Tue Sep 25 16:36:48 2018
        person2@company.com,1.2.3.4:49195,2159230,15413475,Tue Sep 25 16:55:46 2018
        ROUTING TABLE
        Virtual Address,Common Name,Real Address,Last Ref
        10.48.238.4,person2@company.com,1.2.3.4:49195,Tue Sep 25 22:39:36 2018
        10.48.238.2,person3@company.com,5.6.7.8:33874,Tue Sep 25 22:39:43 2018
        10.48.238.3,person1@company.com,9.10.11.12:40743,Tue Sep 25 22:39:28 2018
        GLOBAL STATS
        Max bcast/mcast queue length,0
        END
        ''')
    status_2 = textwrap.dedent('''\
        TITLE,OpenVPN 2.4.6 x86_64-redhat-linux-gnu [Fedora EPEL patched] [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 26 2018
        TIME,Tue Sep 25 22:45:07 2018,1537915507
        HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID
        CLIENT_LIST,person3@company.com,5.6.7.8:33874,10.48.238.2,,16800558,3514403,Tue Sep 25 16:32:49 2018,1537893169,person3,15,1
        CLIENT_LIST,person1@company.com,9.10.11.12:40743,10.48.238.3,,1150910,9991285,Tue Sep 25 16:36:48 2018,1537893408,person1@company.com,16,0
        CLIENT_LIST,person2@company.com,1.2.3.4:49195,10.48.238.4,,2181525,15443089,Tue Sep 25 16:55:46 2018,1537894546,person2@company.com,17,2
        HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)
        ROUTING_TABLE,10.48.238.4,person2@company.com,1.2.3.4:49195,Tue Sep 25 22:45:04 2018,1537915504
        ROUTING_TABLE,10.48.238.2,person3@company.com,5.6.7.8:33874,Tue Sep 25 22:45:05 2018,1537915505
        ROUTING_TABLE,10.48.238.3,person1@company.com,9.10.11.12:40743,Tue Sep 25 22:45:04 2018,1537915504
        GLOBAL_STATS,Max bcast/mcast queue length,0
        END
        ''')
    # status 3 has tabs, beware if copying.
    status_3 = textwrap.dedent('''\
        TITLE	OpenVPN 2.4.6 x86_64-redhat-linux-gnu [Fedora EPEL patched] [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 26 2018
        TIME	Tue Sep 25 22:45:58 2018	1537915558
        HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID
        CLIENT_LIST	person3@company.com	5.6.7.8:33874	10.48.238.2		16806094	3519759	Tue Sep 25 16:32:49 2018	1537893169	person3	15	1
        CLIENT_LIST	person1@company.com	9.10.11.12:4743	10.48.238.3		1151262	9999104	Tue Sep 25 16:36:48 2018	1537893408	person1@company.com	16	0
        CLIENT_LIST	person2@company.com	1.2.3.4:49195	10.48.238.4		2185224	15449627	Tue Sep 25 16:55:46 2018	1537894546	person2@company.com	17	2
        HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
        ROUTING_TABLE	10.48.238.4	person2@company.com	1.2.3.4:49195	Tue Sep 25 22:45:51 2018	1537915551
        ROUTING_TABLE	10.48.238.2	person3@company.com	5.6.7.8:33874	Tue Sep 25 22:45:56 2018	1537915556
        ROUTING_TABLE	10.48.238.3	person1@company.com	9.10.11.12:40743	Tue Sep 25 22:45:57 2018	1537915557
        GLOBAL_STATS	Max bcast/mcast queue length	0
        END
        ''')
    status = {1: status_1, 2: status_2, 3: status_3, }
    good_kill = "SUCCESS: common name 'person1@company.com' found, 1 client(s) killed"
    bad_kill = "ERROR: common name 'sadf' not found"

    def __init__(self, socketfile):
        """
            Create a unix domain socket server that will pretend to be
            the openvpn management server
        """
        # Make sure our server socket filename is ours:
        try:
            # unlink if it's there.  If we succeeded, this completes...
            os.unlink(socketfile)
        except OSError:
            # ... else, there was nothing there (likely) ...
            if os.path.exists(socketfile):
                # ... but if there is, we couldn't delete it, so complain.
                raise
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(socketfile)
        self.sock.listen(1)

    @staticmethod
    def run_a_thread(*args, **kwargs):
        """
            This creates/starts a server thread based on what someone wants
            a test server to act like.  We then start the server, sleep
            ever-so-briefly so that we 'lose' a race condition to the client
            and then return control
        """
        server_thread = threading.Thread(*args, **kwargs)
        server_thread.start()
        time.sleep(0.000001)
        return server_thread

    def server_just_connects(self):
        """ Server that connects but then goes silent """
        client, _addr = self.sock.accept()
        client.send(self.initial_connect)  # pylint: disable=no-member

    def server_hates_you(self):
        """ Pretend a command caused an error """
        client, _addr = self.sock.accept()
        client.send(self.initial_connect)  # pylint: disable=no-member
        time.sleep(0.2)
        # They send something, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send an error back:
        client.send(self.unknown_command)  # pylint: disable=no-member
        time.sleep(0.2)

    def server_status(self, version):
        """ Provide a status to a client """
        client, _addr = self.sock.accept()
        client.send(self.initial_connect)  # pylint: disable=no-member
        time.sleep(0.2)
        # They send something, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send status back:
        client.send(self.status[version])  # pylint: disable=no-member
        time.sleep(0.2)

    def server_status_and_good_kill(self):
        """ Provide a status to a client """
        client, _addr = self.sock.accept()
        client.send(self.initial_connect)  # pylint: disable=no-member
        time.sleep(0.2)
        # They send a request for status, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send status back:
        client.send(self.status[2])  # pylint: disable=no-member
        # They send a kill statement, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send an error back:
        client.send(self.good_kill)  # pylint: disable=no-member
        time.sleep(0.2)

    def server_status_and_bad_kill(self):
        """ Provide a status to a client """
        client, _addr = self.sock.accept()
        client.send(self.initial_connect)  # pylint: disable=no-member
        time.sleep(0.2)
        # They send a request for status, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send status back:
        client.send(self.status[2])  # pylint: disable=no-member
        # They send a kill statement, we ignore.
        client.recv(1024)  # pylint: disable=no-member
        # We send an error back:
        client.send(self.bad_kill)  # pylint: disable=no-member
        time.sleep(0.2)
