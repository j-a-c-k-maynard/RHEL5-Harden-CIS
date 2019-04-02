#!/bin/sh

#
# harden_05_rhel5_cis-v1.1.1sh
##########################################################################
# AUTHOR: HP Consulting - Security & Risk Management, Jack Maynard       #
# Created: May 10, 2010 - HP version 1.0                                 #
#                                                                        #
# RHEL5 Hardening Script Section 5.0 - System Network Parameter Tuning   #
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
#       RHEL5 Benchmark Section 5.0                                      #
#       System Network Parameter Tuning                                  #
#                                                                        #
##########################################################################

##########################################################################
#   5.1 - Network Parameter Modifications                                #
##########################################################################
modify_net_params(){

cat <<END_SCRIPT >> /etc/sysctl.conf

# The following 11 lines added, per
# CIS RHEL5 Benchmark v1.1.1 sec 5.1:
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

END_SCRIPT

    chown root:root /etc/sysctl.conf
    chmod 0600 /etc/sysctl.conf

    # Load new sysctl setting from /etc/sysctl.conf

    sysctl -p

}

##########################################################################
#   5.2 - Additional Network Parameter Modifications                     #
##########################################################################
additional_net_params(){

cat <<END_SCRIPT >> /etc/sysctl.conf

# The following 4 lines added, per
# CIS RHEL5 Benchmark v1.1.1 sec 5.2:
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1

END_SCRIPT

    chown root:root /etc/sysctl.conf
    chmod 0600 /etc/sysctl.conf

    # Load new sysctl setting from /etc/sysctl.conf

    sysctl -p

}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 5.0 - System Network Parameter Tuning                    #
#                                                                        #
##########################################################################

##########################################################################
#   5.1 - Network Parameter Modifications                                #
##########################################################################

modify_net_params

##########################################################################
#   5.2 - Additional Network Parameter Modifications                     #
##########################################################################

additional_net_params

#---------- END   CONFIGURATION ----------#

#----------    END SECTION 5    ----------#

#END
