#!/bin/sh

#
# harden_02_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RHEL5 Hardening Script Section 2.0 - Patches and Additional Software   #
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
#       RHEL5 Benchmark Section 2.0                                      #
#       Patches, Packages and Initial Lockdown                           #
#                                                                        #
##########################################################################

##########################################################################
#   2.1 - Apply latest OS patches                                        #
##########################################################################
apply_patches(){
    
    # This is a manual process. Refer to CIS Benchmark item 2.1.
    
        echo "" > /dev/null
}

##########################################################################
#   2.2 - Validate The System Before Making Changes                      #
##########################################################################
validate_sys(){

    # This is a manual process.  Refer to CIS Benchmark item 2.2.
    
        echo "" > /dev/null
}


##########################################################################
#   2.3 - Configure SSH                                                  #
##########################################################################
set_sshd_param(){
    param=$1
    shift
    value="$@"

    cfg_file=/etc/ssh/sshd_config

    # Escape any '/' for sed.
    value=`echo $value | sed 's|/|\\\/|g'`

    tmpFile=/tmp/sshd_config.$$

    if grep "^ \{0,\}$param \{1,\}" $cfg_file > /dev/null; then
        # The parameter is set already. Ensure it has proper value
        cat $cfg_file | sed "s/^ \{0,\}$param \{1,\}.*/$param $value/" \
                > $tmpFile
        mv $tmpFile $cfg_file

    elif grep "^ \{0,\}#$param \{1,\}$value" $cfg_file > /dev/null; then
        # The parameter exists but is commented out.
        cat $cfg_file | \
                sed "s/^ \{0,\}#$param \{1,\}$value/$param $value/" \
                        > $tmpFile
        mv $tmpFile $cfg_file

    elif grep "^ \{0,\}#$param \{1,\}" $cfg_file > /dev/null; then
        # The parameter exists but is commented out.
        # Replace with proper value.
        cat $cfg_file | sed "s/^ \{0,\}#$param \{1,\}.*/$param $value/" \
                 > $tmpFile
        mv $tmpFile $cfg_file

    else
        # The parameter is not set. Set it.
        echo "$param $value" >> $cfg_file
    fi

    chown root:root $cfg_file
    chmod 600 $cfg_file
}

set_ssh_param(){
    param=$1
    shift
    value="$@"

    cfg_file=/etc/ssh/ssh_config

    # Escape any '/' for sed.
    value=`echo $value | sed 's|/|\\\/|g'`

    tmpFile=/tmp/ssh_config.$$

    if grep "^ \{0,\}$param \{1,\}" $cfg_file > /dev/null; then
        # The parameter is set already. Ensure it has proper value
        cat $cfg_file | sed "s/^ \{0,\}$param \{1,\}.*/$param $value/" \
                > $tmpFile
        mv $tmpFile $cfg_file

    elif grep "^ \{0,\}#$param \{1,\}$value" $cfg_file > /dev/null; then
        # The parameter exists but is commented out.
        cat $cfg_file | \
                sed "s/^ \{0,\}#$param \{1,\}$value/$param $value/" \
                        > $tmpFile
        mv $tmpFile $cfg_file

    elif grep "^ \{0,\}#$param \{1,\}" $cfg_file > /dev/null; then
        # The parameter exists but is commented out.
        # Replace with proper value.
        cat $cfg_file | sed "s/^ \{0,\}#$param \{1,\}.*/$param $value/" \
                 > $tmpFile
        mv $tmpFile $cfg_file

    else
        # The parameter is not set. Set it.
        echo "$param $value" >> $cfg_file
    fi

    chown root:root $cfg_file
    chmod 644 $cfg_file
}

configure_sshd(){
    # CIS Benchmark Recommended settings
    set_sshd_param Protocol 2
    set_sshd_param X11Forwarding yes
    set_sshd_param IgnoreRhosts yes
    set_sshd_param HostbasedAuthentication no
    set_sshd_param RhostsRSAAuthentication no
    set_sshd_param PermitEmptyPasswords no
    set_sshd_param Banner "/etc/issue.net"    
    
    # RIM specific setting that differ from CIS Benchmark
    set_sshd_param RhostsAuthentication yes
    set_sshd_param PermitRootLogin yes  

    # Restart sshd
    /etc/init.d/sshd restart
}

configure_ssh(){
    # CIS Benchmark Recommended settings
    set_ssh_param Protocol 2

    # Restart sshd
    /etc/init.d/sshd restart
}

##########################################################################
#   2.4 - Enable System Accounting                                       #
##########################################################################
enable_sys_acct(){
    if [[ $(rpm -q sysstat | grep not) ]]; then
        yum install sysstat
    fi
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 2.0 - Patches, Packages and Initial Lockdown             #
#                                                                        #
##########################################################################

##########################################################################
#   2.1 - Apply Latest Patches                                           #
##########################################################################

apply_patches

##########################################################################
#   2.2 - Validate The System Before Making Changes                      #
##########################################################################

validate_sys

##########################################################################
#   2.3 - Configure SSH                                                  #
##########################################################################

configure_sshd
configure_ssh

##########################################################################
#   2.4 - Enable System Accounting                                       #
##########################################################################

enable_sys_acct

#---------- END   CONFIGURATION ----------#

#----------    END SECTION 2    ----------#

#END

