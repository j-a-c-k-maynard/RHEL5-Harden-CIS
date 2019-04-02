#!/bin/sh

#
# harden_03_rhel5_cis-v1.1.1sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RHEL5 Hardening Script Section 3.0 - Minimize xinetd Network Services  #
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
#       RHEL5 Benchmark Section 3.0                                      #
#       Minimize xinetd Network Services                                 #
#                                                                        #
##########################################################################

##########################################################################
#   3.1 - Disable Standard Services                                      #
##########################################################################
disable_xinetd_services(){

# Turn off specific services

    for SERVICE in      \
        amanda          \
        chargen         \
        chargen-udp     \
        cups            \
        cups-lpd        \
        daytime         \
        daytime-udp     \
        echo            \
        echo-udp        \
        eklogin         \
        ekrb5-telnet    \
        finger          \
        gssftp          \
        imap            \
        imaps           \
        ipop2           \
        ipop3           \
        klogin          \
        krb5-telnet     \
        kshell          \
        ktalk           \
        ntalk           \
        rexec           \
        rlogin          \
        rsh             \
        rsync           \
        talk            \
        tcpmux-server   \
        telnet          \
        tftp            \
        time-dgram      \
        time-stream     \
        uucp;
    do
        if [ -e /etc/xinetd.d/$SERVICE ]; then
            chkconfig ${SERVICE} off
            chkconfig --list ${SERVICE}
        fi
    done
}

##########################################################################
#   3.2 - Configure TCP Wrappers and Firewall to Limit Access            #
##########################################################################
config_tcp_wrappers(){

    # The below assumes a netmask of 255.255.255.0. (/24)
    
    # Site-specific /etc/host.allow, this variable MUST be configured
    ALLOW=$(echo "ALL: localhost, 10.")
    DENY=$(echo "ALL: ALL")
    
    printf "$ALLOW" > /etc/hosts.allow
    printf "$DENY"  > /etc/hosts.deny

    chown root:root /etc/hosts.allow /etc/hosts.deny
    chmod 0644 /etc/hosts.allow /etc/hosts.deny

}

##########################################################################
#   3.3 - Only Enable telnet if Absolutely Necessary                     #
##########################################################################
enable_telnet(){
    if [ -e /etc/xinetd.d/telnet ]; then
        chkconfig telnet on
        chkconfig --list telnet
    fi
}

##########################################################################
#   3.4 - Only Enable FTP if Absolutely Necessary                        #
##########################################################################
enable_ftp(){
    if [ -e /etc/xinetd.d/vsftpd ]; then
        chkconfig --levels 35 vsftpd on
        chkconfig --list vsftpd
    fi
}

##########################################################################
#   3.5 - Only Enable rlogin/rsh/rcp if Absolutely Necessary             #
##########################################################################
enable_rlogin(){
    for SERVICE in login rlogin rsh shell; do
        if [ -e /etc/xinetd.d/$SERVICE ]; then
            chkconfig ${SERVICE} on
            chkconfig --list ${SERVICE}
        fi
    done
}

##########################################################################
#   3.6 - Only Enable TFTP if Absolutely Necessary                       #
##########################################################################
enable_tftp(){
    if [ -e /etc/xinetd.d/tftp ]; then
        chkconfig --levels 35 tftp on
        chkconfig --list tftp
    fi

    if [ -e "/tftpboot" ] ; then
        chown -R root:root /tftpboot
        chmod -R 0744 /tftpboot
    else
        mkdir -m 0744 /tftpboot && chown root:root /tftpboot
    fi
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 3.0 - Minimize xinetd Network Services                   #
#                                                                        #
##########################################################################

##########################################################################
#   3.1 - Disable Standard Services                                      #
##########################################################################

disable_xinetd_services

##########################################################################
#   3.2 - Configure TCP Wrappers and Firewall to Limit Access            #
##########################################################################

#config_tcp_wrappers

##########################################################################
#   3.3 - Only Enable telnet if Absolutely Necessary                     #
##########################################################################

#enable_telnet

##########################################################################
#   3.4 - Only Enable FTP if Absolutely Necessary                        #
##########################################################################

#enable_ftp

##########################################################################
#  3.5 - Only Enable rlogin/rsh/rcp if Absolutely Necessary              #
##########################################################################

#enable_rlogin

##########################################################################
#   3.6 - Only Enable TFTP if Absolutely Necessary                       #
##########################################################################

#enable_tftp

#---------- END  CONFIGURATION ----------#

#----------    END SECTION 3   ----------#

#END
