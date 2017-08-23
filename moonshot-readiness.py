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
INDENT = "    "

cmd = os.popen('which hostname 2>/dev/null')
bin_hostname = (cmd.read()).strip()
cmd = os.popen('which dig 2>/dev/null')
bin_dig = (cmd.read()).strip()
cmd = os.popen('which grep 2>/dev/null')
bin_grep = (cmd.read()).strip()
cmd = os.popen('which echo 2>/dev/null')
bin_echo = (cmd.read()).strip()
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
cmd = os.popen('which dpkg 2>/dev/null')
bin_dpkg = (cmd.read()).strip()
# Mac specific
cmd = os.popen('which sw_vers 2>/dev/null')
bin_swvers = (cmd.read()).strip()



#=================================  PRINT OKAY/WARN/FAIL BANNER  =============================



def print_summary(colour, text_string, endl):

    colour_tag = ""
    if (colour == bcolors.OKBLUE or colour == bcolors.OKGREEN):
        colour_tag = "[OKAY]"
    elif (colour == bcolors.WARNING):
        colour_tag = "[WARN]"
    elif (colour == bcolors.FAIL):
        colour_tag = "[FAIL]"

    print(INDENT + text_string.ljust(47) + colour + colour_tag + bcolors.ENDC + endl)



#=================================  TESTS BASIC  ===========================================



def test_basic():
    global results
    global is_rhel
    global is_mac
    print("\n\nTesting task basic...")

#Supported OS

    good_os = False
    is_rhel = False
    is_mac = False
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
    elif os.path.isfile(bin_swvers) == True:
        cmd = os.popen('%s 2>&1' % bin_swvers)
        lines = cmd.read().strip().split("\n")
        i = 0
        while i < len(lines):
            words = lines[i].split(":")
            if words[0].lower() == "productname":
                name = words[1].strip()
            elif words[0].lower() == "productversion":
                rel_ver = words[1].strip().split(".")[1]
            i = i + 1
        rel_os = name.lower().split()[0]

#OS checking: We support Debian, Ubuntu, RHEL, CentOS, Scientific Linux, macOS (client)
    if (rel_os == 'debian'):
        good_os = (rel_ver == '8' or rel_ver == '9')
    elif (rel_os == 'ubuntu'):
        good_os = (rel_ver == '12' or rel_ver == '14' or rel_ver == '16')
    elif (rel_os == 'redhat' or rel_os == 'rhel' or rel_os == 'centos' or rel_os == 'scientific'):
        is_rhel = True
        good_os = (rel_ver == '6' or rel_ver == '7')
    elif (rel_os == 'mac'):
        is_mac = True
        good_os = (rel_ver == '11' or rel_ver == '12' or rel_ver == '13')

    if good_os == True:
        print_summary(bcolors.OKGREEN, "Supported OS...", "")
    else:
        print_summary(bcolors.WARNING, "Supported OS...", "")
        results = results + INDENT + "Supported OS:\n        You are not running a supported OS. Moonshot may not work as indicated in the documentation.\n"

#Check for prerequisites (like dig etc)
    fail_basic_req = (bin_hostname == "" or bin_dig == "" or bin_grep == "" or bin_echo == "")
    if (not is_mac):
        if (is_rhel):
             if (fail_basic_req or bin_yum == "" or bin_rpm == ""):
                 print_summary(bcolors.FAIL, "Some prerequisites couldn\'t be found.", "")
                 results = results + INDENT + "Prerequisites for this test:\n        One or more prerequisites for this test couldn\'t be found. Please check that dig, hostname, grep, echo, yum and rpm are installed.\n"
                 return
        else:
             if (fail_basic_req or bin_aptcache == "" or bin_aptget == "" or bin_aptkey == "" or bin_dpkg == ""):
                 print_summary(bcolors.FAIL, "Some prerequisites couldn\'t be found.", "")
                 results = results + INDENT + "Prerequisites for this test:\n        One or more prerequisites for this test couldn\'t be found. Please check that dig, hostname, grep, echo, apt-get, apt-key, apt-cache and dpkg are installed.\n"
                 return

#Hostname is FQDN
    cmd = os.popen("%s -f" % bin_hostname)
    fqdn1 = (cmd.read()).strip()
    cmd = os.popen("%s %s +short" % (bin_dig, fqdn1))
    address = (cmd.read()).strip()
    if len(address) == 0:
         print_summary(bcolors.FAIL, "Hostname is FQDN...", "")
         results = results + INDENT + "Hostname is FQDN:\n        Your server\'s hostname ("+fqdn1+") is not fully resolvable. This is required in order to prevent certain classes of attack.\n"
    else:      
        cmd = os.popen("%s -x %s +short" % (bin_dig, address))
        fqdn2 = (cmd.read()).strip()
        if fqdn1 + "." == fqdn2:
            print_summary(bcolors.OKGREEN, "Hostname is FQDN...", "")
        else:
            print_summary(bcolors.FAIL, "Hostname is FQDN...", "")
            results = results + INDENT + "Hostname is FQDN:\n        Your server\'s IP address " + address + " is not resolvable to '" + fqdn1 + "' instead script got '" + fqdn2.strip('.') + "'. This is required in order to prevent certain classes of attack.\n"

#Moonshot repository configuration
    if (not is_mac):
        if (is_rhel == True):
            cmd = os.popen('%s -q list all "moonshot-gss-eap" 2>&1' % bin_yum)
        else:
            cmd = os.popen('%s search -n "moonshot-gss-eap"' % bin_aptcache)
        cmd_result = cmd.read()
        if (cmd_result.lower().find('moonshot-gss-eap') >= 0):
            print_summary(bcolors.OKGREEN, "Moonshot repositories configured...", "")
        else:
            print_summary(bcolors.WARNING, "Moonshot repositories configured...", "")
            results = results + INDENT + "Moonshot repositories configured:\n        The Moonshot repositories do not appear to exist on this system. You will not be able to upgrade Moonshot using your distribution\'s package manager.\n"

#Moonshot Signing Key
    if (not is_mac):
        if (is_rhel == True):
            cmd = os.popen("%s %s" % (bin_rpm, " -q gpg-pubkey --qf '%{version} %{summary}\n'"))
        else:
            cmd = os.popen('%s --keyring /etc/apt/trusted.gpg list' % bin_aptkey)
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
            print_summary(bcolors.OKGREEN, "Moonshot Signing Key...", "")
        else:
            print_summary(bcolors.WARNING, "Moonshot Signing Key...", "")
            results = results + INDENT + "Moonshot Signing Key:\n        The Moonshot repository key is not installed, you will have difficulty updating packages.\n"

#Current Moonshot software
    if (not is_mac):
        if (is_rhel == True):
            cmd = os.popen('%s --assumeno install moonshot-gss-eap 2>&1' % bin_yum)
        else:
            cmd = os.popen('%s --assume-no install moonshot-gss-eap' % bin_aptget)
        cmd = cmd.read()
        if (cmd.find("0 newly installed") >= 0) or (cmd.find("0 to newly install") >= 0) or (cmd.find("already the newest version") >= 0) \
            or (cmd.find("already installed and latest version") >= 0) or ((cmd.find("Nothing to do") >= 0) and (cmd.find("Error: Nothing to do") < 0)):
            print_summary(bcolors.OKGREEN, "Moonshot current version...", "\n\n")
        else:
            print_summary(bcolors.WARNING, "Moonshot current version...", "\n\n")
            results = results + INDENT + "Moonshot current version:\n        You are not running the latest version of the Moonshot software.\n"



#=================================  TESTS RP  ===========================================



def test_rp():
    global results
    global is_mac
    test_basic()
    print("Testing task rp...")

#Not supported on macOS
    if (is_mac):
        print_summary(bcolors.FAIL, "Configuration not supported on macOS", "")
        results = results + INDENT + "Configuration not supported on macOS:\n        macOS is currently only supported in a client configuration.\n"
        return

#/etc/radsec.conf
    if os.path.isfile("/etc/radsec.conf") == True:
        print_summary(bcolors.OKGREEN, "radsec.conf...", "\n\n")
    else:
        print_summary(bcolors.FAIL, "radsec.conf...", "\n\n")
        results = results + INDENT + "radsec.conf:\n        /etc/radsec.conf could not be found - you may not be able to communicate with your rp-proxy.\n"



#=================================  TESTS RP-PROXY  ===========================================



def test_rp_proxy():
    global results
    test_rp()
    print("Testing task rp-proxy...")

#Not supported on macOS
    if (is_mac):
        print_summary(bcolors.FAIL, "Configuration not supported on macOS", "")
        results = results + INDENT + "Configuration not supported on macOS:\n        macOS is currently only supported in a client configuration.\n"
        return

#APC
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('ov-apc.moonshot.ja.net', 2083))
    if result == 0:
        print_summary(bcolors.OKGREEN, "APC...", "")
    else:
        print_summary(bcolors.FAIL, "APC...", "")
        results = results + INDENT + "APC:\n        ov-apc.moonshot.ja.net does not seem to be accessible. Please check the servers network connection, and see status.moonshot.ja.net for any downtime or maintenance issues.\n"

#Trust Router
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('tr.moonshot.ja.net', 12309))
    if result == 0:
        print_summary(bcolors.OKGREEN, "Trust Router...", "")
    else:
        print_summary(bcolors.FAIL, "Trust Router...", "")
        results = results + INDENT + "Trust Router:\n        tr.moonshot.ja.net does not seem to be accessible. Please check the servers network connection, and see status.moonshot.ja.net for any downtime or maintenance issues.\n"

#flatstore-users
    root = False
    freerad = False
    trustrouter = False
    if os.path.isfile("/etc/moonshot/flatstore-users") == True:
        fil = open("/etc/moonshot/flatstore-users", "r")
        for line in fil:
            if line.strip() == "root":
                root = True
            elif line.strip() == "trustrouter":
                trustrouter = True
            elif (line.strip() == "freerad" or line.strip() == "radiusd"):
                freerad = True
        fil.close()
    if root == True and freerad == True and trustrouter == True:
        print_summary(bcolors.OKGREEN, "Flatstore-users...", "")
    else:
        print_summary(bcolors.FAIL, "Flatstore-users...", "")
        results = results + INDENT + "Flatstore-users:\n        /etc/moonshot/flatstore-users could not be found, or does not contain all the user accounts it needs to. You may be unable to authenticate to the trust router.\n"
        

#Trust Identity for FreeRADIUS
    if (is_rhel == True):
        cmd = os.popen('%s ~radiusd' % bin_echo)
    else:
        cmd = os.popen('%s ~freerad' % bin_echo)
    raduserhome = cmd.read().strip()

    if (raduserhome == '~radiusd' or raduserhome == '~freerad'):
        print_summary(bcolors.FAIL, "Trust Identity (FreeRADIUS)...", "\n\n")
        results = results + INDENT + "Trust Identity (FreeRADIUS):\n        FreeRADIUS does not appear to be installed, or no home directory for the FreeRADIUS user could be found. You will not be able to authenticate to the trust router.\n"
    elif os.path.isfile(raduserhome + '/.local/share/moonshot-ui/identities.txt') == True:
        print_summary(bcolors.OKGREEN, "Trust Identity (FreeRADIUS)...", "\n\n")
    else:
        print_summary(bcolors.FAIL, "Trust Identity (FreeRADIUS)...", "\n\n")
        results = results + INDENT + "Trust Identity (FreeRADIUS):\n        No trust identity could be found for the FreeRADIUS user account. You will not be able to authenticate to the trust router.\n"



#=================================  TESTS IDP  ===========================================



def test_idp():
    global results
    global is_rhel
    test_rp()
    print("Testing task idp...")

#Not supported on macOS
    if (is_mac):
        print_summary(bcolors.FAIL, "Configuration not supported on macOS", "")
        results = results + INDENT + "Configuration not supported on macOS:\n        macOS is currently only supported in a client configuration.\n"
        return

#Port 2083
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', 2083))
    if result == 0:
        print_summary(bcolors.OKGREEN, "Port 2083...", "")
    else:
        print_summary(bcolors.FAIL, "Port 2083...", "")
        results = results + INDENT + "Port 2083:\n        Port 2083 appears to be closed. RP's will not be able to initiate connections to your IDP.\n"

#Port 12309
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', 12309))
    if result == 0:
        print_summary(bcolors.OKGREEN, "Port 12309...", "")
    else:
        print_summary(bcolors.FAIL, "Port 12309...", "")
        results = results + INDENT + "Port 12309:\n        Port 12309 appears to be closed. The trust router will not be able to initiate connections to your IDP.\n"

#flatstore-users
    root = False
    freerad = False
    trustrouter = False
    if os.path.isfile("/etc/moonshot/flatstore-users") == True:
        fil = open("/etc/moonshot/flatstore-users", "r")
        for line in fil:
            if line.strip() == "root":
                root = True
            elif line.strip() == "trustrouter":
                trustrouter = True
            elif (line.strip() == "freerad" or line.strip() == "radiusd"):
                freerad = True
        fil.close()
    if root == True and freerad == True and trustrouter == True:
        print_summary(bcolors.OKGREEN, "Flatstore-users...", "")
    else:
        print_summary(bcolors.FAIL, "Flatstore-users...", "")
        results = results + INDENT + "Flatstore-users:\n        /etc/moonshot/flatstore-users could not be found, or does not contain all the user accounts it needs to. You may be unable to authenticate to the trust router.\n"
        
#Trust Identity for FreeRADIUS
    if (is_rhel == True):
        cmd = os.popen('%s ~radiusd' % bin_echo)
    else:
        cmd = os.popen('%s ~freerad' % bin_echo)
    raduserhome = cmd.read().strip()

    if (raduserhome == '~radiusd' or raduserhome == '~freerad'):
        print_summary(bcolors.FAIL, "Trust Identity (FreeRADIUS)...", "")
        results = results + INDENT + "Trust Identity (FreeRADIUS):\n        FreeRADIUS does not appear to be installed, or no home directory for the FreeRADIUS user could be found. You will not be able to authenticate to the trust router.\n"
    elif os.path.isfile(raduserhome + '/.local/share/moonshot-ui/identities.txt') == True:
        print_summary(bcolors.OKGREEN, "Trust Identity (FreeRADIUS)...", "")
    else:
        print_summary(bcolors.FAIL, "Trust Identity (FreeRADIUS)...", "")
        results = results + INDENT + "Trust Identity (FreeRADIUS):\n        No trust identity could be found for the FreeRADIUS user account. You will not be able to authenticate to the trust router.\n"


#Trust Identity for TIDS
    cmd = os.popen('%s ~trustrouter' % bin_echo)
    trustrouterhome = cmd.read().strip()

    if (trustrouterhome == '~trustrouter'):
        print_summary(bcolors.FAIL, "Trust Identity (Trust Router)...", "\n\n")
        results = results + INDENT + "Trust Identity (Trust Router):\n        There either is no trustrouter user or no home directory for the trustrouter user could be found. You will not be able to authenticate to the trust router.\n"
    elif os.path.isfile(trustrouterhome + '/.local/share/moonshot-ui/identities.txt') == True:
        print_summary(bcolors.OKGREEN, "Trust Identity (Trust Router)...", "\n\n")
    else:
        print_summary(bcolors.FAIL, "Trust Identity (Trust Router)...", "\n\n")
        results = results + INDENT + "Trust Identity (Trust Router):\n        No trust identity could be found for the trustrouter user account. You will not be able to authenticate to the trust router.\n"



#=================================  TESTS CLIENT  ===========================================



def test_client():
    global results
    global is_rhel
    global is_mac
    test_basic()
    print("Testing task client...")

#gss/mech
    s1 = False
    s2 = False
    if (is_rhel or is_mac):
        gss_mech = '/etc/gss/mech'
    else:
        gss_mech = '/etc/gss/mech.d/moonshot-gss-eap.conf'

    if os.path.isfile(gss_mech) == True:
        mode = oct(stat.S_IMODE(os.stat(gss_mech)[stat.ST_MODE]))
        if mode.strip() == "0644":
            string1 = ['eap-aes128', '1.3.6.1.5.5.15.1.1.17', 'mech_eap.so'] 
            string2 = ['eap-aes256', '1.3.6.1.5.5.15.1.1.18', 'mech_eap.so']
            fil = open(gss_mech,"r")
            for line in fil:
                words=re.split(r'[ \t]+', line.strip())
                # The length of the list must be 3 (mechanism name, mechanism oid, mechanism binary)
                if (len(words)>2):
                    if (not s1):
                        s1 = (string1[0] in words[0]) and (string1[1] in words[1]) and (string1[2] in words[2])
                    if (not s2):
                        s2 = (string2[0] in words[0]) and (string2[1] in words[1]) and (string2[2] in words[2])
            fil.close()
            
    if (s1 == True and s2 == True):
        print_summary(bcolors.OKGREEN, "gss/mech...", "\n\n")
    else:
        print_summary(bcolors.FAIL, "gss/mech...", "\n\n")
        results = results + INDENT + "gss/mech:\n        The Moonshot mech file is missing or incomplete. mech_eap.so will not be loaded.\n"



#=================================  TESTS SSH-CLIENT  ===========================================



def test_ssh_client():
    global results
    global is_mac
    test_client()
    print("Testing task ssh-client...")

    cmd = os.popen('which ssh 2>/dev/null')
    cmd = (cmd.read()).strip()
    is_ssh_installed = (len(cmd) > 0)

    if (is_ssh_installed == False):
        print_summary(bcolors.FAIL, "Task ssh-client...", "\n\n")
        results = results + INDENT + "Task ssh-client:\n        You must have OpenSSH installed before attempting this test.\n"

    else:

#GSSAPIAuthentication must be enabled
        num = 0
        cmd = os.popen("%s %s" % (bin_grep, " GSSAPIAuthentication /etc/ssh/ssh_config |grep -v \#"))
        cmd = (cmd.read()).strip()
        if len(cmd) > 0:
            lines = cmd.split('\n')
            for line in lines:
                if (line.lower() == 'gssapiauthentication yes'):
                    num = num + 1
            if num > 0:
                print_summary(bcolors.OKGREEN, "GSSAPIAuthentication enabled...", "")
            else:
                print_summary(bcolors.FAIL, "GSSAPIAuthentication enabled...", "")
                results = results + INDENT + "GSSAPIAuthentication enabled:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"
        else:
            print_summary(bcolors.FAIL, "GSSAPIAuthentication enabled...", "")
            results = results + INDENT + "GSSAPIAuthentication enabled:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"

#GSSAPIKeyExchange (should be) enabled
        if (not is_mac):
            num = 0
            cmd = os.popen("%s %s" % (bin_grep, " GSSAPIKeyExchange /etc/ssh/ssh_config |grep -v \#"))
            cmd = (cmd.read()).strip()
            if len(cmd) > 0:
                lines = cmd.split('\n')
                for line in lines:
                    if (line.lower() == 'gssapikeyexchange yes'):
                        num = num + 1
                if num > 0:
                    print_summary(bcolors.OKGREEN, "GSSAPIKeyExchange enabled...", "\n\n")
                else:
                    print_summary(bcolors.WARNING, "GSSAPIKeyExchange enabled...", "\n\n")
                    results = results + INDENT + "GSSAPIKeyExchange enabled:\n        GSSAPIKeyExchange should be enabled for Moonshot to function correctly when using SSH.\n"
            else:
                print_summary(bcolors.WARNING, "GSSAPIKeyExchange enabled...", "\n\n")
                results = results + INDENT + "GSSAPIKeyExchange enabled:\n        GSSAPIKeyExchange should be enabled for Moonshot to function correctly when using SSH.\n"



#=================================  TESTS SSH-SERVER  ===========================================



def test_ssh_server():
    global results
    test_rp()
    print("Testing task ssh-server...")

#Not supported on macOS
    if (is_mac):
        print_summary(bcolors.FAIL, "Configuration not supported on macOS", "")
        results = results + INDENT + "Configuration not supported on macOS:\n        macOS is currently only supported in a client configuration.\n"
        return

    cmd = os.popen('/usr/sbin/sshd -V 2>&1 |grep OpenSSH')
    cmd = (cmd.read()).strip()
    is_openssh_installed = (len(cmd) > 0)

    if (is_openssh_installed == False):
        print_summary(bcolors.FAIL, "Task ssh-server...", "\n\n")
        results = results + INDENT + "Task ssh-server:\n        You must have OpenSSH installed before attempting this test.\n"

    else:
        openssh = (((cmd.split()[0]).split('_')[1]).split('p')[0]).split('.')
        needs_privsepoff = (int(openssh[0]) < 6) or (int(openssh[0]) == 6 and int(openssh[1]) < 6)

#GSSAPIAuthentication enabled
        num = 0
        cmd = os.popen("%s %s" % (bin_grep, " GSSAPIAuthentication /etc/ssh/sshd_config |grep -v \#"))
        cmd = (cmd.read()).strip()
        if len(cmd) > 0:
            lines = cmd.split('\n')
            for line in lines:
                if (line.lower() == 'gssapiauthentication yes'):
                    num = num + 1
            if num > 0:
                print_summary(bcolors.OKGREEN, "GSSAPIAuthentication enabled...", "")
            else:
                print_summary(bcolors.FAIL, "GSSAPIAuthentication enabled...", "")
                results = results + INDENT + "GSSAPIAuthentication enabled:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"
        else:
            print_summary(bcolors.FAIL, "GSSAPIAuthentication enabled...", "")
            results = results + INDENT + "GSSAPIAuthentication enabled:\n        GSSAPIAuthentication must be enabled for Moonshot to function when using SSH.\n"

#GSSAPIKeyExchange enabled
        num = 0
        cmd = os.popen("%s %s" % (bin_grep, " GSSAPIKeyExchange /etc/ssh/sshd_config |grep -v \#"))
        cmd = (cmd.read()).strip()
        if len(cmd) > 0:
            lines = cmd.split('\n')
            for line in lines:
                if (line.lower() == 'gssapikeyexchange yes'):
                    num = num + 1
            if num > 0:
                print_summary(bcolors.OKGREEN, "GSSAPIKeyExchange enabled...", "")
            else:
                print_summary(bcolors.FAIL, "GSSAPIKeyExchange enabled...", "")
                results = results + INDENT + " enabled:\n        GSSAPIKeyExchange must be enabled for Moonshot to function correctly when using SSH.\n"
        else:
            print_summary(bcolors.FAIL, "GSSAPIKeyExchange enabled...", "")
            results = results + INDENT + "GSSAPIKeyExchange enabled:\n        GSSAPIKeyExchange must be enabled for Moonshot to function correctly when using SSH.\n"

#UsePrivilegeSeparation disabled
        if (needs_privsepoff == True):
            num = 0
            cmd = os.popen("%s %s" % (bin_grep, " UsePrivilegeSeparation /etc/ssh/sshd_config |grep -v \#"))
            cmd = (cmd.read()).strip()
            if len(cmd) > 0:
                lines = cmd.split('\n')
                for line in lines:
                    if (line.lower() == 'useprivilegeseparation no'):
                        num = num + 1
                if num > 0:
                    print_summary(bcolors.OKGREEN, "Privilege separation...", "\n\n")
                else:
                    print_summary(bcolors.FAIL, "Privilege separation...", "\n\n")
                    results = results + INDENT + "Privilege separation:\n        Moonshot currently requires that OpenSSH server has privilege separation disabled.\n\n"
            else:
                print_summary(bcolors.FAIL, "Privilege separation...", "")
                results = results + INDENT + "Privilege separation:\n        Moonshot currently requires that OpenSSH server has privilege separation disabled.\n\n"
        else:
            print("\n")



#=================================  MAIN  ===========================================



size = len(sys.argv)

if size < 2 :
    print("\n\nUsage: moonshot-readiness [task] [task]...\n\n  Available tasks:\n    help\n    minimal (default)\n    client\n    rp\n    rp-proxy\n    idp\n    ssh-client\n    ssh-server\n\n")

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
        elif (sys.argv[i]).strip() == 'idp':
            test_idp()
        elif (sys.argv[i]).strip() == 'ssh-client':
            test_ssh_client()
        elif (sys.argv[i]).strip() == 'ssh-server':
            test_ssh_server()
        else:
            print ("\n\nTask \"" + sys.argv[i] + "\" doesn't exist.\n  Available tasks:\n    minimal (default)\n    client\n    rp\n    rp-proxy\n    idp-proxy\n    ssh-client\n    ssh-server\n\n")
            sys.exit()
        i = i+1

    if results == "====================================================================================\n\nTest complete, failed tests:\n":
        results = "====================================================================================\n\nTest complete, 100% is OKAY\n\n"
    print results
