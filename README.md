moonshot-readiness
==================

Script to test the state of a Moonshot deployment.

===============================  MOONSHOT-READINESS  ===============================


Usage: moonshot-readiness [task] [task]...

  Available tasks:
    help
    minimal (default)
    client
    rp
    rp-proxy
    idp
    ssh-client
    ssh-server

This script supports the following OSes:

Linux: 
    RedHat, CentOS, Scientific Linux: 6 or 7
    Debian: 8 or 9
    Ubuntu: 12, 14, 16
    
macOS:
    10.11, 10.12, 10.13 (beta)

Note: Some of the functionality requires this script to be run with root/elevated privileges.
