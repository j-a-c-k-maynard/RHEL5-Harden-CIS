#!/bin/sh

#
# do-install_RHEL5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RedHat Enterprise Linux 5 (RHEL5)  Security Hardening INSTALL Script   #
# This script installs the HP Security hardening scripts package.        #
# Scripted to Center for Internet Security (CIS) RHEL5 Benchmark v1.1.1  #
# www.cisecurity.org                                                     #
##########################################################################

# Create hpharden user account and set password.

    /usr/sbin/useradd -u '2000' -g 'users' -d '/home/hpharden' -s '/bin/bash' \
        -c 'HP Hardening' -p '$1$/UBl4fdh$wa4woBkxV.8V9FfcEFofg/' 'hpharden' &> /dev/null
    
# Set secure permissions

    cd /opt; chmod -R 700 ./hp &> /dev/null

# Clean up some unnecessary debug files created by rpmbuild

    rm -f /debug*list
    rm -f /find_requires
    
# END
