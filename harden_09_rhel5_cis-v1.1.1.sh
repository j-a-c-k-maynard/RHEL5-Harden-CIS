#!/bin/sh

#
# harden_09_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RHEL5 Hardening Script Section 9.0 - User Accounts and Environment     #
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
#       RHEL5 Benchmark Section 9.0                                      #
#       User Accounts and Environment                                    #
#                                                                        #
##########################################################################

##########################################################################
#   9.1 - Block Login of System Accounts                                 #
##########################################################################
block_system_accounts(){

    cd /etc

    for NAME in `cut -d: -f1 /etc/passwd`;
    do
         MyUID=`id -u $NAME`

        if [ $MyUID -lt 500 -a $NAME != 'root' ]; then
        
            usermod -L -s /dev/null $NAME
        fi
    done

    chown root:root /etc/passwd
    chmod 0644 /etc/passwd

    chown root:root /etc/shadow
    chmod 0400 /etc/shadow

}

##########################################################################
#   9.2 -  Verify That There Are No Accounts With Empty Password Fields  #
##########################################################################
check_empty_passwd(){

    # Review CIS-CAT Report for a list of accounts with empty passwords.
    
        echo "" > /dev/null

}

##########################################################################
#   9.3 - Set Account Expiration Parameters On Active Accounts           #
##########################################################################
set_expire(){

    # The login.defs manpage indicates these functions are now all
    # handled by PAM.  This changes the defaults applicable to new
    # accounts added to the system after this point.
    
    FILE="/etc/login.defs"
    
    if [ -e $FILE ]; then

    cp ${FILE} ${FILE}.tmp

    awk '($1 ~ /^PASS_MAX_DAYS/) { $2="90" }
         ($1 ~ /^PASS_MIN_DAYS/) { $2="7" }
         ($1 ~ /^PASS_WARN_AGE/) { $2="14" }
         ($1 ~ /^PASS_MIN_LEN/)  { $2="8" }
         { print }' ${FILE}.tmp > ${FILE}
         
    rm ${FILE}.tmp

    useradd -D -f 7

    fi
    
    # This applies the same basis of changes to existing accounts.
    # -m: (7) The number of days between permitted password changes.
    # -M: (90) The maximum number of days a password is valid.
    # -W: (14) The maximum number of days of advanced warning before a
    # password is no longer valid.
    # -I: (7) The maximum number of days of inactivity, after a password
    # has expired, before the account is locked.

    for NAME in `cut -d: -f1 /etc/passwd`;
    do
        uid=`id -u $NAME`

        if [ $uid -ge 500 -a $uid != 65534 ];
        then
            chage -m 7 -M 90 -W 14 -I 7 $NAME
        fi
    done

cat <<END_SCRIPT >> ${FILE}
# Establish a forced five-second minimum delay between failed logins
FAIL_DELAY 5
END_SCRIPT

    chown root:root ${FILE}
    chmod 0640 ${FILE}
}

##########################################################################
#   9.4 - Verify No Legacy '+' Entries Exist In passwd,shadow,group Files#
##########################################################################
no_legacy_plus(){

    # Review CIS-CAT Report for listing of legacy '+' entries

    chown root:root /etc/shadow /etc/gshadow
    chmod 0400 /etc/shadow /etc/gshadow
    
}

##########################################################################
#   9.5 - No '.' or Group/World-Writable Directory In Root's PATH        #
##########################################################################
check_root_path(){

    # Review CIS-CAT Report for listing of '.' or group/world-writable
    # directories in root's PATH.
    
    echo "" > /dev/null

}

##########################################################################
#   9.6 - User Home Directories Should Be Mode 0750 or More Restrictive  #
##########################################################################
check_user_home_perms(){

    for DIR in `awk -F: '( $3 >= 500 ) { print $6 }' /etc/passwd`;
    do
        if [ $DIR != /var/lib/nfs ];
        then
            chmod -R g-w $DIR
            chmod -R o-rwx $DIR
        fi
    done
}

##########################################################################
#   9.7 - No User Dot-Files Should Be World-Writable                     #
##########################################################################
set_user_dot_files(){

    for DIR in `awk -F: '($3 >= 500) { print $6 }' /etc/passwd`;
    do
        for FILE in $DIR/.[A-Za-z0-9]*;
        do
            if [ ! -h "$FILE" -a -f "$FILE" ];
            then
                chmod go-w "$FILE"
            fi
        done
    done
}

##########################################################################
#   9.8 - Remove user .netrc Files                                       #
##########################################################################
remove_netrc_files(){

    # Refer to CIS-CAT Report for list of user .netrc files.
    
    echo "" > /dev/null

}

##########################################################################
#   9.9 - Set Default umask For Users                                    #
##########################################################################
set_default_umask(){

    # Forced umask assignment into /etc/skel/.bashrc for consistency

    echo "umask 077" >> /etc/bashrc
    echo "umask 077" >> /etc/csh.cshrc
    echo "umask 077" >> /etc/csh.login
    echo "umask 077" >> /etc/profile
    echo "umask 077" >> /etc/skel/.bashrc

    echo "umask 077" >> /root/.bashrc
    echo "umask 077" >> /root/.cshrc
    echo "umask 077" >> /root/.tcshrc
    echo "umask 077" >> /root/.bash_profile

    chown root:root /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/profile
    chmod 0444 /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/profile
    
    chown root:root /root/.bash_profile /root/.bashrc /root/.cshrc /root/.tcshrc
    chmod 0400 /root/.bash_profile /root/.bashrc /root/.cshrc /root/.tcshrc
    
}

##########################################################################
#   9.10 - Disable Core Dumps                                            #
##########################################################################
disable_core_dumps(){

    FILE="/etc/security/limits.conf"

    if [ -e $FILE ]; then
    
        cp ${FILE} ${FILE}.tmp

        awk '( $1 == "#*" && $2 == "soft" && $3 == "core" && $4 == "0" ) \
             {  print "* soft core 0"; \
               print "* hard core 0"; next } \
             { print }' ${FILE}.tmp > ${FILE}

        chown root:root ${FILE}
        chmod 0644 ${FILE}
    
        rm ${FILE}.tmp
    
    fi
}

##########################################################################
#   9.11 - Limit Access To The Root Account From su                      #
##########################################################################
limit_su_root(){

    # Be sure to add all admins to the 'wheel' group before executing
    # By executing this ONLY members of the wheel group can su to root.
    
    FILE="/etc/pam.d/su"
    
    if [ -e $FILE ]; then
        cp ${FILE} ${FILE}.tmp

        awk '( $1=="#auth" && $2=="required" && $3~"pam_wheel.so" ) \
             { print "auth\t\trequired\t",$3,"\tuse_uid"; next };
             { print }' ${FILE}.tmp > ${FILE}

        chown root:root ${FILE}
        chmod 0644 ${FILE}
    
        rm ${FILE}.tmp
 
    fi
}


#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 9.0 - User Accounts and Environment                      #
#                                                                        #
##########################################################################

##########################################################################
#   9.1 - Block Login of System Accounts                                 #
##########################################################################

block_system_accounts

##########################################################################
#   9.2 -  Verify That There Are No Accounts With Empty Password Fields  #
##########################################################################

check_empty_passwd

##########################################################################
#   9.3 - Set Account Expiration Parameters On Active Accounts           #
##########################################################################

set_expire

##########################################################################
#   9.4 - Verify No Legacy '+' Entries Exist In passwd,shadow,group Files#
##########################################################################

no_legacy_plus

##########################################################################
#   9.5 - No '.' or Group/World-Writable Directory In Root's $PATH       #
##########################################################################

check_root_path

##########################################################################
#   9.6 - User Home Directories Should Be Mode 0750 or More Restrictive  #
##########################################################################

check_user_home_perms

##########################################################################
#   9.7 - No User Dot-Files Should Be World-Writable                     #
##########################################################################

set_user_dot_files

##########################################################################
#   9.8 - Remove user .netrc Files                                       #
##########################################################################

remove_netrc_files

##########################################################################
#   9.9 - Set Default umask For Users                                    #
##########################################################################

set_default_umask

##########################################################################
#   9.10 - Disable Core Dumps                                            #
##########################################################################

#disable_core_dumps

##########################################################################
#   9.11 - Limit Access To The Root Account From su                      #
##########################################################################

limit_su_root

#---------- END  CONFIGURATION ----------#

#----------    END SECTION 9   ----------#

#END
