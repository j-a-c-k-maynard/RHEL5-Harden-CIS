#!/bin/sh

#
# harden_04_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RHEL5 Hardening Script Section 4.0 - Minimize Boot Services            #
# Scripted to Center for Internet Security (CIS) RHEL5 Benchmark v1.1.1  #
# www.cisecurity.org                                                     #
##########################################################################

# Variable Declarations

# Redirect stdout and stderr to /dev/null, this helps reduce screen noise.
# Change /dev/null to a real file for debugging purposes.

    STDOUT_STDERR="/dev/null"
    exec &>${STDOUT_STDERR}

##########################################################################
#                                                                        #
#       RHEL5 Benchmark Section 4.0                                      #
#       Minimize Boot Services                                           #
#                                                                        #
##########################################################################

##########################################################################
#   4.1 - Set Daemon umask                                               #
##########################################################################
set_daemon_umask(){

    UMASK="027"
    
    FILE1="/etc/sysconfig/init"
    
    if [ -e $FILE1 ]; then
    
        echo "umask ${UMASK}" >> ${FILE1}

        chown root:root ${FILE1}
        chmod 0755 ${FILE1}
        
    fi
    
    FILE2="/etc/rc.d/init.d/functions"
    
    if [ -e $FILE2 ]; then
    
        cp ${FILE2} ${FILE2}.tmp
        sed 's/022/027/' ${FILE2}.tmp > ${FILE2}
        rm ${FILE2}.tmp
        
    fi
}

##########################################################################
#   4.2 - Disable xinetd, If Possible                                    #
##########################################################################
disable_xinetd(){
    if [ -e /etc/init.d/xinetd ]; then
        chkconfig --level 12345 xinetd off
        chkconfig --list xinetd
    fi
}

##########################################################################
#   4.3 - Ensure sendmail is only listing to the localhost, If Possible  #
##########################################################################
local_sendmail(){
    if [ -e /etc/init.d/sendmail ]; then
        echo "DAEMON=no" > /etc/sysconfig/sendmail
        echo "QUEUE=1h" >> /etc/sysconfig/sendmail

        chkconfig --level 12345 sendmail off
        chkconfig --list sendmail

        chown root:root /etc/sysconfig/sendmail
        chmod 0644 /etc/sysconfig/sendmail
    fi
}

##########################################################################
#   4.4 - Disable GUI Login If Possible                                  #
##########################################################################
disable_gui_login(){

    FILE="/etc/inittab"
    
    if [ -e $FILE ]; then
    
        cp ${FILE} ${FILE}.tmp
    
        sed -e 's/id:5:initdefault:/id:3:initdefault:/' \
            ${FILE}.tmp > ${FILE}
        
        rm ${FILE}.tmp

        chown root:root ${FILE}
        chmod 0600 ${FILE}    
    fi
}

##########################################################################
#   4.5 - Disable X Font Server If Possible                              #
##########################################################################
disable_xfont_server(){
    if [ -e /etc/init.d/xfs ]; then
        chkconfig --level 12345 xfs off
        chkconfig --list xfs
    fi
}

##########################################################################
#   4.6 - Disable Standard Boot Services                                 #
##########################################################################
disable_boot_services(){

    # Enable (do not disable) per RIM business requirements
    
    # httpd (WWW)
    # nfslock (NFS Client)
    # portmap (NFS)
    # rpcgssd (RPC Services)
    # rpcidmapd (RPC Services)
    # rpcsvcgssd (RPC Services)
    # snmpd
    # tomcat5 (WWW)
    # tux (WWW)
    # webmin (WWW)

    # Disable (do not enable) per CIS Benchmark requirements
    
    for SERVICE in              \
        acpid                   \
        amd                     \
        anacron                 \
        apmd                    \
        aprwatch                \
        arptables_jf            \
        atd                     \
        autofs                  \
        avahi-daemon            \
        avahi-dnsconfd          \
        bluetooth               \
        bootparamd              \
        bpgd                    \
        canna                   \
        capi                    \
        conman                  \
        cups                    \
        cups-config-daemon      \
        cyrus-imapd             \
        dc_client               \
        dc_server               \
        dhcdbd                  \
        dhcp6s                  \
        dhcpd                   \
        dhcrelay                \
        dovecot                 \
        dund                    \
        firstboot               \
        FreeWnn                 \
        gpm                     \
        haldaemon               \
        hidd                    \
        hplip                   \
        hpoj                    \
        ibmasm                  \
        innd                    \
        iptables                \
        ip6tables               \
        ipmi                    \
        irda                    \
        iscsi                   \
        iscsid                  \
        isdn                    \
        kadmin                  \
        kdcrotate               \
        kdump                   \
        kprop                   \
        krb524                  \
        krb5kdc                 \
        kudzu                   \
        ldap                    \
        lisa                    \
        lm_sensors              \
        lvs                     \
        mailman                 \
        mars-nwe                \
        mcstrans                \
        mdmonitor               \
        mdmpd                   \
        messagebus              \
        microcode_ctl           \
        multipathd              \
        mysqld                  \
        named                   \
        netfs                   \
        netplugd                \
        NetworkManager          \
        nfs                     \
        nscd                    \
        ntpd                    \
        oki4daemon              \
        openibd                 \
        ospf6d                  \
        ospfd                   \
        pand                    \
        pcscd                   \
        postgresql              \
        privoxy                 \
        privoxy                 \
        psacct                  \
        radvd                   \
        rarpd                   \
        rdisc                   \
        readahead_early         \
        readahead_later         \
        rhnsd                   \
        ripd                    \
        ripngd                  \
        rstatd                  \
        rusersd                 \
        rwalld                  \
        rwhod                   \
        saslauthd               \
        setroubleshoot          \
        smartd                  \
        smb                     \
        snmptrapd               \
        spamassassin            \
        squid                   \
        tog-pegasus             \
        winbind                 \
        wine                    \
        wpa_supplicant          \
        xend                    \
        xendomains              \
        ypbind                  \
        yppasswdd               \
        ypserv                  \
        ypxfrd                  \
        zebra;

    do
        if [ -e /etc/init.d/${SERVICE} ]; then      
            chkconfig --level 12345 ${SERVICE} off
            chkconfig --list ${SERVICE}
        fi

    done
}

##########################################################################
#   4.7 - Only Enable SMB (Windows File Sharing) Processes, If Necessary #
##########################################################################
enable_smb(){
    if [ -e /etc/init.d/smb ]; then
        chkconfig --level 35 smb on
        chkconfig --list smb
    fi
}

##########################################################################
#   4.8 - Only Enable NFS Server Processes, If Absolutely Necessary      #
##########################################################################
enable_nfs_server(){
    for SERVICE in nfs nfslock portmapper rpc; do
        if [ -e /etc/init.d/${SERVICE} ]; then
            chkconfig --level 35 ${SERVICE} on
            chkconfig --list ${SERVICE}
        fi
    done
}

##########################################################################
#   4.9 - Only Enable NFS Client Processes, If Absolutely Necessary      #
##########################################################################
enable_nfs_client(){
    if [ -e /etc/init.d/nfslock ]; then
        chkconfig --level 35 nfslock on
        chkconfig --list nfslock
    fi
}

##########################################################################
#   4.10 - Only enable NIS Client Processes, If Absolutely Necessary     #
##########################################################################
enable_nis_client(){
    if [ -e /etc/init.d/ypbind ]; then
        chkconfig --level 35 ypbind on
        chkconfig --list ypbind
    fi
}

##########################################################################
#   4.11 - Only Enable NIS Server Processes, If Absolutely Necessary     #
##########################################################################
enable_nis_server(){
    for SERVICE in ypserv yppasswdd; do
        if [ -e /etc/init.d/${SERVICE} ]; then
            chkconfig --level 35 ${SERVICE} on
            chkconfig --list ${SERVICE}
        fi
    done
}

##########################################################################
#   4.12 - Only Enable RPC Portmap Process, If Absolutely Necessary      #
##########################################################################
enable_portmap(){
    if [ -e /etc/init.d/portmap ]; then
        chkconfig --level 35 portmap on
        chkconfig --list portmap
    fi
}

##########################################################################
#   4.13 - Only Enable netfs Script, If Absolutely Necessary             #
##########################################################################
enable_netfs(){
    if [ -e /etc/init.d/netfs ]; then
        chkconfig --level 35 netfs on
        chkconfig --list netfs
    fi
}

##########################################################################
#   4.14 - Only Enable Printer Daemon Processes, If Absolutely Necessary #
##########################################################################
enable_cups(){

    if [ -e /etc/init.d/cups ]; then

        cp /etc/cups/cupsd.conf /tmp/cupsd.conf

        sed -e 's/^\#User lp/User lp/' -e 's/^\#Group sys/Group sys/' \
                /tmp/cupsd.conf > /etc/cups/cupsd.conf
        
        rm /tmp/cupsd.conf

        chown lp:sys /etc/cups/cupsd.conf
        chmod 0600 /etc/cups/cupsd.conf

        chkconfig --level 35 cups on
        chkconfig --list cups
    fi
}

##########################################################################
#   4.15 - Only Enable Web Server Processes, If Absolutely Necessary     #
##########################################################################
enable_web(){
    for SERVICE in apache httpd tux; do
        if [ -e /etc/init.d/${SERVICE} ]; then
            chkconfig --level 35 ${SERVICE} on
            chkconfig --list ${SERVICE}
	fi
    done
}

##########################################################################
#   4.16 - Only Enable SNMP Processes, If Absolutely Necessary           #
##########################################################################
enable_snmpd(){
    if [ -e /etc/init.d/snmpd ]; then
        chkconfig --level 35 snmpd on
        chkconfig --list snmpd
    fi
}

##########################################################################
#   4.17 - Only Enable DNS Server Process, If Absolutely Necessary       #
##########################################################################
enable_named(){
    if [ -e /etc/init.d/named ]; then
        chkconfig --level 35 named on
        chkconfig --list named
    fi
}

##########################################################################
#   4.18 - Only Enable SQL Server Processes, If Absolutely Necessary     #
##########################################################################
enable_sql(){
    for SERVICE in postgresql mysqld; do
        if [ -e /etc/init.d/${SERVICE} ]; then
            chkconfig --level 35 ${SERVICE} on
            chkconfig --list ${SERVICE}
        fi
    done
}

##########################################################################
#   4.19 - Only Enable Squid Cache Server, If Absolutely Necessary       #
##########################################################################
enable_squid(){
    if [ -e /etc/init.d/squid ]; then
        chkconfig --level 35 squid on
        chkconfig --list squid
    fi
}

##########################################################################
#   4.20 - Only Enable Kudzu Hardware Detection, If Absolutely Necessary #
##########################################################################
enable_kudzu(){
    if [ -e /etc/init.d/kudzu ]; then
        chkconfig --level 35 kudzu on
        chkconfig --list kudzu
    fi
}

##########################################################################
#   4.21 - Only Enable cyrus-imapd, If Absolutely Necessary              #
##########################################################################
enable_cyrus_imapd(){
    if [ -e /etc/init.d/cyrus-imapd ]; then
        chkconfig --level 35 cyrus-imapd on
        chkconfig --list cyrus-imapd
    fi
}

##########################################################################
#   4.22 - Only Enable dovecot, If Absolutely Necessary                  #
##########################################################################
enable_dovecot(){
    if [ -e /etc/init.d/dovecot ]; then
        chkconfig --level 35 dovecot on
        chkconfig --list dovecot
    fi
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 4.0 - Minimize Boot Services                             #
#                                                                        #
##########################################################################

##########################################################################
#   4.1 - Set Daemon umask                                               #
##########################################################################

set_daemon_umask

##########################################################################
#   4.2 - Disable xinetd, If Possible                                    #
##########################################################################

disable_xinetd

##########################################################################
#   4.3 - Ensure sendmail is only listening to the localhost, If Possible#
##########################################################################

local_sendmail

##########################################################################
#   4.4 - Disable GUI Login, If Possible                                 #
##########################################################################

disable_gui_login

##########################################################################
#   4.5 - Disable X Font Server, If Possible                             #
##########################################################################

disable_xfont_server

##########################################################################
#   4.6 - Disable Standard Boot Services                                 #
##########################################################################

disable_boot_services

##########################################################################
#   4.7 - Only Enable SMB (Windows File Sharing) Processes, If Necessary #
##########################################################################

#enable_smb

##########################################################################
#   4.8 - Only Enable NFS Server Processes, If Absolutely Necessary      #
##########################################################################

#enable_nfs_server

##########################################################################
#   4.9 - Only Enable NFS Client Processes, If Absolutely Necessary      #
##########################################################################

enable_nfs_client

##########################################################################
#   4.10 - Only Enable NIS Client Processes, If Absolutely Necessary     #
##########################################################################

#enable_nis_client

##########################################################################
#   4.11 - Only Enable NIS Server Processes, If Absolutely Necessary     #
##########################################################################

#enable_nis_server

##########################################################################
#   4.12 -  Only Enable RPC Portmap Process, If Absolutely Necessary      #
##########################################################################

enable_portmap

##########################################################################
#   4.13 - Only Enable netfs Script, If Absolutely Necessary             #
##########################################################################

#enable_netfs

##########################################################################
#   4.14 - Only Enable Printer Daemon Processes, If Absolutely Necessary #
##########################################################################

#enable_cups

##########################################################################
#   4.15 - Only Enable Web Server Processes, If Absolutely Necessary     #
##########################################################################

enable_web

##########################################################################
#   4.16 - Only Enable SNMP Processes, If Absolutely Necessary           #
##########################################################################

enable_snmpd

##########################################################################
#   4.17 - Only Enable DNS Server Process, If Absolutely Necessary       #
##########################################################################

#enable_named

##########################################################################
#   4.18 - Only Enable SQL Server Processes, If Absolutely Necessary     #
##########################################################################

#enable_sql

##########################################################################
#   4.19 - Only Enable Squid Cache Server, If Absolutely Necessary       #
##########################################################################

#enable_squid

##########################################################################
#   4.20 - Only Enable Kudzu Hardware Detection, If Absolutely Necessary #
##########################################################################

#enable_kudzu

##########################################################################
#   4.21 - Only Enable cyrus-imapd, If Absolutely Necessary              #
##########################################################################

#enable_cyrus_imapd

##########################################################################
#   4.22 - Only Enable dovecot, If Absolutely Necessary                  #
##########################################################################

#enable_dovecot
    
#---------- END CONFIGURATION ----------#

#----------    END SECTION 4   ---------#

#END
