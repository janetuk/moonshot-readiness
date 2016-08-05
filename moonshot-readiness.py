#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import os
import socket
import sys
import stat
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


print "\n\n===============================  MOONSHOT-READINESS  ==============================="
results = "====================================================================================\n\nTest complete, failed tests:\n"

cmd = os.popen('which hostname 2>/dev/null')
bin_hostname = (cmd.read()).strip()
cmd = os.popen('which dig 2>/dev/null')
bin_dig = (cmd.read()).strip()
cmd = os.popen('which grep 2>/dev/null')
bin_grep = (cmd.read()).strip()
# RHEL specific
cmd = os.popen('which yum 2>/dev/null')
bin_yum = (cmd.read()).strip()
cmd = os.popen('which rpm 2>/dev/null')
bin_rpm = (cmd.read()).strip()
# Debian specific
cmd = os.popen('which apt-cache 2>/dev/null')
bin_aptcache = (cmd.read()).strip()
cmd = os.popen('which apt-key 2>/dev/null')
bin_aptkey = (cmd.read()).strip()
cmd = os.popen('which apt-get 2>/dev/null')
bin_aptget = (cmd.read()).strip()


#=================================  TESTS BASIC  ===========================================



def test_basic():
    global results
    print("\n\nTesting task basic...")

#Hostname is FQDN

    cmd = os.popen("%s -f" % bin_hostname)
    fqdn1 = (cmd.read()).strip()
    cmd = os.popen("%s %s +short" % (bin_dig, fqdn1))
    address = (cmd.read()).strip()
    if len(address) == 0:
         print("    Hostname is FQDN...                            " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
         results = results + "    Hostname is FQDN:\n        Your server\'s hostname ("+fqdn1+") is not fully resolvable. This is required in order to prevent certain classes of attack.\n"
    else:      
        cmd = os.popen("%s -x %s +short" % (bin_dig, address))
        fqdn2 = (cmd.read()).strip()
        if fqdn1 + "." == fqdn2:
            print("    Hostname is FQDN...                            " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
        else:
            print("    Hostname is FQDN...                            " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
            results = results + "    Hostname is FQDN:\n        Your server\'s IP address " + address + " is not resolvable to '" + fqdn1 + "' instead script got '" + fqdn2.strip('.') + "'. This is required in order to prevent certain classes of attack.\n"


#Supported OS

    good_os = False
    is_rhel = False
    rel_os = ""
    rel_ver = ""
    if os.path.isfile("/etc/os-release") == True:
        fil = open("/etc/os-release", "r")
        text = fil.read()
        fil.close()
        lines = text.split("\n")
        i = 0
        while i < len(lines):
            words = lines[i].split("=")
            if words[0] == "ID":
                rel_os = words[1].strip("\"")
            elif words[0] == "VERSION_ID":
                rel_ver = words[1].strip("\"").split(".")[0]
            i = i + 1
    elif os.path.isfile("/etc/redhat-release") == True:
        fil = open("/etc/redhat-release", "r")
        name = (fil.read()).strip().split(".")[0].lower()
        fil.close()
        rel_ver = name.rsplit(" ", 1)[1]
        rel_os = name.split(" ")[0]

    # now for the OS checking: We support Debian, Ubuntu, RHEL, CentOS, Scientific Linux
    if (rel_os == 'debian'):
        good_os = (rel_ver == '7' or rel_ver == '8')
    elif (rel_os == 'ubuntu'):
        good_os = (rel_ver == '12' or rel_ver == '14')
    elif (rel_os == 'redhat' or rel_os == 'rhel' or rel_os == 'centos' or rel_os == 'scientific'):
        is_rhel = True
        good_os = (rel_ver == '6' or rel_ver == '7')

    if good_os == True:
        print("    Supported OS...                                " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Supported OS...                                " + bcolors.WARNING + "[WARN]" + bcolors.ENDC + "")
        results = results + "    Supported OS:\n        You are not running a supported OS. Moonshot may not work as indicated in the documentation.\n"


#Moonshot repository configuration

    if (is_rhel == True):
        cmd = os.popen('%s -q list all "moonshot-gss-eap" 2>&1' % bin_yum)
    else:
        cmd = os.popen('%s search -n "moonshot-gss-eap"' % bin_aptcache)
    cmd_result = cmd.read()
    if (cmd_result.lower().find('moonshot-gss-eap') >= 0):
        print("    Moonshot repositories configured...            " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Moonshot repositories configured...            " + bcolors.WARNING + "[WARN]" + bcolors.ENDC + "")
        results = results + "    Moonshot repositories configured:\n        The Moonshot repositories do not appear to exist on this system. You will not be able to upgrade Moonshot using your distributions package manager.\n"


#Moonshot Signing Key

    if (is_rhel == True):
        cmd = os.popen("%s %s" % (bin_rpm, " -q gpg-pubkey --qf '%{version} %{summary}\n'"))
    else:
        cmd = os.popen("%s --keyring /etc/apt/trusted.gpg list" % bin_aptkey)
    cmd = cmd.read()
    key1 = False
    key2 = False
    words=re.split(r'[ \t\n/]+', cmd.upper())
    i = 0
    while i < len(words):
        if words[i] == "5B8179FD":
            key1 = True
        elif words[i] == "CEA67BB6":
            key2 = True
        i = i + 1
    if (key1 == True or key2 == True):
        print("    Moonshot Signing Key...                        " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Moonshot Signing Key...                        " + bcolors.WARNING + "[WARN]" + bcolors.ENDC + "")
        results = results + "    Moonshot Signing Key:\n        The Moonshot repository key is not installed, you will have difficulty updating packages.\n"


#Current version

    if (is_rhel == True):
        cmd = os.popen("%s -q --assumeno install moonshot-gss-eap 2>&1" % bin_yum)
    else:
        cmd = os.popen("%s --assume-no install moonshot-gss-eap" % bin_aptget)
    cmd = cmd.read()
    if (cmd.find("0 newly installed") >= 0) or (cmd.find("0 to newly install") >= 0) or (cmd.find("already the newest version") >= 0) or (cmd.find("already installed and latest version") >= 0):
        print("    Moonshot current version...                    " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    Moonshot current version...                    " + bcolors.WARNING + "[WARN]" + bcolors.ENDC + "\n\n")
        results = results + "    Moonshot current version:\n        You are not running the latest version of the Moonshot software.\n"



#=================================  TESTS RP  ===========================================



def test_rp():
    global results
    test_basic()
    print("Testing task rp...")


#/etc/radsec.conf

    cmd = os.path.isfile("/etc/radsec.conf")
    if cmd == True:
        print("    radsec.conf...                                 " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    radsec.conf...                                 " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "\n\n")
        results = results + "    radsec.conf:\n        /etc/radsec.conf could not be found - you may not be able to communicate with your rp-proxy.\n"



#=================================  TESTS RP-PROXY  ===========================================



def test_rp_proxy():
    global results
    test_rp()
    print("Testing task rp-proxy...")


#APC

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('ov-apc.moonshot.ja.net', 2083))
    if result == 0:
        print("    APC...                                         " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    APC...                                         " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    APC:\n        ov-apc.moonshot.ja.net does not seem to be accessible. Please check the servers network connection, and see status.moonshot.ja.net for any downtime or maintenance issues.\n"


#Trust Router

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('tr.moonshot.ja.net', 12309))
    if result == 0:
        print("    Trust Router...                                " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Trust Router...                                " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Trust Router:\n        tr.moonshot.ja.net does not seem to be accessible. Please check the servers network connection, and see status.moonshot.ja.net for any downtime or maintenance issues.\n"


#flatstore-users

    root = False
    freerad = False
    if os.path.isfile("/etc/moonshot/flatstore-users") == True:
        fil = open("/etc/moonshot/flatstore-users", "r")
        for line in fil:
            if line.strip() == "root":
                root = True
            if line.strip() == "freerad":
                freerad = True
        fil.close()
    if root == True and freerad == True:
        print("    Flatstore-users...                             " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Flatstore-users...                             " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Flatstore-users:\n        /etc/moonshot/flatstore-users could not be found, or does not contain all the user accounts it needs to. You may be unable to authenticate to the trust router.\n"
        

#Trust Identity

    if os.path.isfile("/etc/freeradius/.local/share/moonshot-ui/identities.txt") == True:
        print("    Trust Identity...                              " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    Trust Identity...                              " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "\n\n")
        results = results + "    Trust Identity:\n        No trust identity could be found for the freeradius user account. You will not be able to authenticate to the trust router.\n"



#=================================  TESTS IDP  ===========================================



def test_idp():
    global results
    test_rp()
    print("Testing task idp...")


#Port 2083

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', 2083))
    if result == 0:
        print("    Port 2083...                                   " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Port 2083...                                   " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Port 2083:\n        Port 2083 appears to be closed. RP's will not be able to initiate connections to your IDP.\n"


#Port 12309

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', 12309))
    if result == 0:
        print("    Port 12309...                                  " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Port 12309...                                  " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Port 12309:\n        Port 12309 appears to be closed. The trust router will not be able to initiate connections to your IDP.\n"


#flatstore-users

    root = False
    freerad = False
    if os.path.isfile("/etc/moonshot/flatstore-users") == True:
        fil = open("/etc/moonshot/flatstore-users", "r")
        for line in fil:
            if line.strip() == "root":
                root = True
            if line.strip() == "freerad":
                freerad = True
        fil.close()
    if root == True and freerad == True:
        print("    Flatstore-users...                             " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Flatstore-users...                             " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Flatstore-users:\n        /etc/moonshot/flatstore-users could not be found, or does not contain all the user accounts it needs to. You may be unable to authenticate to the trust router.\n"


#Trust Identity

    if os.path.isfile("/etc/freeradius/.local/share/moonshot-ui/identities.txt") == True:
        print("    Trust Identity...                              " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    Trust Identity...                              " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "\n\n")
        results = results + "    Trust Identity:\n        No trust identity could be found for the freeradius user account. You will not be able to authenticate to the trust router.\n"



#=================================  TESTS CLIENT  ===========================================



def test_client():
    global results
    test_basic()
    print("Testing task client...")


#gss/mech

    cmd = os.path.isfile("/usr/etc/gss/mech") 
    if cmd == True:
        mode = oct(stat.S_IMODE(os.stat("/usr/etc/gss/mech")[stat.ST_MODE]))
        if mode.strip() == "0644":
            
            string1 = "eap-aes128 1.3.6.1.5.5.15.1.1.17 mech_eap.so" 
            string2 = "eap-aes128 1.3.6.1.5.5.15.1.1.17 mech_eap.so"
            s1 = False
            s2 = False
            fil = open("/usr/etc/gss/mech","r")
            for line in fil:
                words=re.split(r'[ \t]+', line)
                i = 0
                str_reg = ""
                while i < len(words):
                    str_reg = str_reg + words[i] + " "
                    i = i+1
                if string1 == str_reg.strip():
                    s1 = True
                if string2 == str_reg.strip():
                    s2 = True
            fil.close()
            
            if (s1 == True and s2 == True):
                print("    gss/mech...                                    " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
                return;

    print("    gss/mech...                                    " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "\n\n")
    results = results + "    gss/mech:\n        The Moonshot mech file is missing mech_eap.so will not be loaded.\n"



#=================================  TESTS SSH-CLIENT  ===========================================



def test_ssh_client():
    global results
    test_client()
    print("Testing task ssh-client...")


#GSSAPIAuthentication enabled

    cmd = os.popen("augtool print /files/etc/ssh/ssh_config/Host/GSSAPIAuthentication")
    cmd = cmd.read()
    if cmd.strip() == "/files/etc/ssh/ssh_config/Host/GSSAPIAuthentication = \"yes\"":
        print("    GSSAPIAuthentication enabled...                " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    GSSAPIAuthentication enabled...                " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    GSSAPIAuthentication enabled:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"


#GSSAPIKeyExchange enabled

    cmd = os.popen("augtool print /files/etc/ssh/ssh_config/Host/GSSAPIKeyExchange")
    cmd = cmd.read()
    if cmd.strip() == "/files/etc/ssh/ssh_config/Host/GSSAPIKeyExchange = \"yes\"":
        print("    GSSAPIKeyExchange enabled...                   " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    GSSAPIKeyExchange enabled...                   " + bcolors.WARNING + "[WARN]" + bcolors.ENDC + "\n\n")
        results = results + "    GSSAPIKeyExchange enabled:\n        GSSAPIKeyExchange should be enabled for Moonshot to function correctly when using SSH.\n"



#=================================  TESTS SSH-SERVER  ===========================================



def test_ssh_server():
    global results
    test_rp()
    print("Testing task ssh-client...")


#Privilege separation disabled

    cmd = os.popen("augtool print /files/etc/ssh/sshd_config/UsePrivilegeSeparation")
    cmd = cmd.read()
    if cmd.strip() == "/files/etc/ssh/sshd_config/UsePrivilegeSeparation = \"no\"":
        print("    Privilege separation disabled...               " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "")
    else:
        print("    Privilege separation disabled...               " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "")
        results = results + "    Privilege separation disabled:\n        Moonshot currently requires that OpenSSH server has privilege separation disabled.\n"


#GSSAPIAuthentication

    cmd = os.popen("augtool print /files/etc/ssh/sshd_config/GSSAPIAuthentication")
    cmd = cmd.read()
    if cmd.strip() == "/files/etc/ssh/sshd_config/GSSAPIAuthentication = \"yes\"":
        print("    GSSAPIAuthentication...                        " + bcolors.OKGREEN + "[OKAY]" + bcolors.ENDC + "\n\n")
    else:
        print("    GSSAPIAuthentication...                        " + bcolors.FAIL + "[FAIL]" + bcolors.ENDC + "\n\n")
        results = results + "    GSSAPIAuthentication:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"



#=================================  MAIN  ===========================================



size = len(sys.argv)

if size < 2 :
    print("\n\nUsage: moonshot-readiness [task] [task]...\n\n  Available tasks:\n    help\n    minimal (default)\n    client\n    rp\n    rp-proxy\n    idp-proxy\n    ssh-client\n    ssh-server\n\n")

else:
    i = 1
    while i < size:
        if (sys.argv[i]).strip() == 'help':
            print "\n\nUsage: moonshot-readiness [task] [task]...\n\n  Available tasks:\n    help\n    minimal (default)\n    client\n    rp\n    rp-proxy\n    idp-proxy\n    ssh-client\n    ssh-server\n\n  ¦---------------------------------------------------------------------------------------------------------------¦\n  ¦ TASK            ¦  DEPENDENCY  ¦  DESCRIPTION                                                                 ¦\n  ¦-----------------¦--------------¦------------------------------------------------------------------------------¦\n  ¦ basic           ¦  none        ¦  Basic set of test, required for Moonshot to function at all in any capacity ¦\n  ¦ client          ¦  basic       ¦  Fundamental tests required for Moonshot to function as a client             ¦\n  ¦ rp              ¦  basic       ¦  Fundamental tests required for Moonshot to function as an RP                ¦\n  ¦ rp-proxy        ¦  rp          ¦  Tests required for Moonshot to function as a RadSec RP                      ¦\n  ¦ idp             ¦  rp          ¦  Tests to verify if FreeRADIUS is correctly configured                       ¦\n  ¦ openssh-client  ¦  client      ¦  Tests to verify if the openssh-client is correctly configured               ¦\n  ¦ openssh-rp      ¦  rp          ¦  Tests to verify if the openssh-server is correctly configured               ¦\n  ¦ httpd-client    ¦  client      ¦  Tests to verify if mod-auth-gssapi is correctly configured                  ¦\n  ¦ httpd-rp        ¦  rp          ¦  Tests to verify if mod-auth-gssapi is correctly configured                  ¦\n  ¦-----------------¦--------------¦------------------------------------------------------------------------------¦\n\n\nSome tests require root privileges to be made.\nSome tests require the following tools:\n  augeas     (installing with apt-get install augeas-tools)\n  dig        (installing with apt-get install dnsutils)\n  hostname   (installing with apt-get install hostname)\n\n"


            sys.exit()
        elif (sys.argv[i]).strip() == 'minimal':
            test_basic()
        elif (sys.argv[i]).strip() == 'client':
            test_client()
        elif (sys.argv[i]).strip() == 'rp':
            test_rp()
        elif (sys.argv[i]).strip() == 'rp-proxy':
            test_rp_proxy()
        elif (sys.argv[i]).strip() == 'idp-proxy':
            test_idp()
        elif (sys.argv[i]).strip() == 'ssh-client':
            test_ssh_client()
        elif (sys.argv[i]).strip() == 'ssh-server':
            test_ssh_server()
        else:
            print ("\n\nTask \"" + sys.argv[i] + "\" doesn't exist.\n  Available tasks:\n    minimal (default)\n    client\n    rp\n    rp-proxy\n    idp-proxy\n    ssh-client\n    ssh-server\n\n")
            sys.exit()
        i = i+1

    if results == "=========================================================================\n\nTest complete, failed tests:\n":
        results = "=========================================================================\n\nTest complete, 100% is OKAY\n\n"
    print results
