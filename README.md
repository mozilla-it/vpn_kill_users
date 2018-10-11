# vpn_kill_users
This script is designed to be fired at regular intervals, looking for users who should be disconnected from the VPN.

If found, they will be disconnected.

Must be run with sufficient privileges to connect to the openvpn management interface.

This script was formerly part of the duo_openvpn package, but it was a misfit utility there, and was split out.
