#!/bin/sh

#
# harden_11_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: HP Consulting - Security & Risk Management, Jack Maynard       #
# Created: May 10, 2010 - HP version 1.0                                 #
#                                                                        #
# RHEL5 Hardening Script Section 11.0 - Misc Odds and Ends               #
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
#       RHEL5 Benchmark Section 11.0                                     #
#       Misc Odds and Ends                                               #
#                                                                        #
##########################################################################

##########################################################################
#   11.1 - Configure and Enable the auditd and sysstat Services          #
##########################################################################
enable_auditd_sysstat(){

    # Part 1 - Enforce auditing minimums"
    
    FILE1="/etc/audit/audit.rules"
    
    if [ -e $FILE1 ]; then

    /bin/cp -pf ${FILE1} ${FILE1}.tmp

    cat <<END_SCRIPT > ${FILE1}.tmp

## This file contains the auditctl rules that are loaded
## whenever the audit daemon is started via the initscripts.
## The rules are simply the parameters that would be passed
## to auditctl.
##
## First rule - delete all

-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems

-b 8192

## Set failure mode to syslog notice {these two are mutually exclusive}

-f 1

## Set failure mode to panic {these two are mutually exclusive}
## -f 2

## NOTE:
## 1) if this is being used on a 32 bit machine, comment out the b64 lines
## 2) These rules assume that login under the root account is not allowed.
## 3) It is also assumed that 500 represents the first usable user account.
## 4) If these rules generate too much spurious data for your tastes, limit the
## the syscall file rules with a directory, like -F dir=/etc
## 5) You can search for the results on the key fields in the rules
##
## (GEN002880: CAT II) The IAO will ensure the auditing software can
## record the following for each audit event:
##- Date and time of the event
##- Userid that initiated the event
##- Type of event
##- Success or failure of the event
##- For I&A events, the origin of the request (e.g., terminal ID)
##- For events that introduce an object into a user's address space, and
## for object deletion events, the name of the object, and in MLS
## systems, the object's security level.
##

## Things that could affect time

-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change

#-a always,exit -F arch=b32 -S clock_settime -k time-change
#-a always,exit -F arch=b64 -S clock_settime -k time-change

-w /etc/localtime -p wa -k time-change

## Things that affect identity

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Things that could affect system locale

-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

## Things that could affect MAC policy

-w /etc/selinux/ -p wa -k MAC-policy

## The SysAdmin will configure the auditing system to audit the following events
## for all users and root:
## - Logon (unsuccessful and successful) and logout (successful)
## This is handled by pam, sshd, login, and gdm
## Might also want to watch these files if needing extra information
# -w /var/log/faillog -p wa -k logins
# -w /var/log/lastlog -p wa -k logins
##- Process and session initiation (unsuccessful and successful)
##
## The session initiation is audited by pam without any rules needed.
## Might also want to watch this file if needing extra information
#-w /var/run/utmp -p wa -k session
#-w /var/log/btmp -p wa -k session
#-w /var/log/wtmp -p wa -k session

##- Discretionary access control permission modification (unsuccessful
## and successful use of chown/chmod)

-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

##- Unauthorized access attempts to files (unsuccessful)

-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

##- Use of privileged commands (unsuccessful and successful)

## use find /bin -type f -perm -04000 2>/dev/null and put all those files in
## a rule like this
-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

##- Use of print command (unsuccessful and successful)
##- Export to media (successful)
## You have to mount media before using it. You must disable all automounting
## so that its done manually in order to get the correct user requesting the
## export

-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export

##- System startup and shutdown (unsuccessful and successful)
##- Files and programs deleted by the user (successful and unsuccessful)

-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

##- All system administration actions
##- All security personnel actions
##
## Look for pam_tty_audit and add it to your login entry point's pam configs.
## If that is not found, use sudo which should be patched to record its
## commands to the audit system. Do not allow unrestricted root shells or
## sudo cannot record the action.

-w /etc/sudoers -p wa -k actions

## Optional - could indicate someone trying to do something bad or
## just debugging
#-a entry,always -F arch=b32 -S ptrace -k tracing
#-a entry,always -F arch=b64 -S ptrace -k tracing

## Optional - could be an attempt to bypass audit or simply legacy program
#-a always,exit -F arch=b32 -S personality -k bypass
#-a always,exit -F arch=b64 -S personality -k bypass

## Put your own watches after this point
# -w /your-file -p rwxa -k mykey

## Make the configuration immutable - reboot is required to change audit rules

-e 2

END_SCRIPT

    cp -pf ${FILE1}.tmp ${FILE1}
    
    chown root:root ${FILE1}
    chmod 0600 ${FILE1}
    
    rm ${FILE1}.tmp
    
    fi
    
    # Part 2 - Strengthen auditd.conf settings"
    
    FILE2="/etc/audit/auditd.conf"
    
    if [ -e $FILE2 ]; then
    
        cp -pf ${FILE2} ${FILE2}.tmp
    
        sed -e "s/num_logs = 4/num_logs = 5/" \
        -e "s/max_log_file = 5/max_log_file = 100/" \
        -e "s/space_left = 75/space_left = 125/" \
        -e "s/admin_space_left = 50/admin_space_left = 75/" \
        -e "s/space_left_action = SYSLOG/space_left_action = email/" \
        ${FILE2}.tmp > ${FILE2}
    
    chown root:root ${FILE2}
    chmod 0600 ${FILE2}
    
    rm ${FILE2}.tmp
    
    fi    
    
    # Part 3 - Make auditd applicable across reboots."
    
    chkconfig --level 35 auditd on
    chkconfig --level 35 sysstat on
    
    # Enable auditd and sysstat services, good even if rebooting soon
    
    service auditd restart
    service sysstat restart
    
}

##########################################################################
#   11.2 - Verify No Duplicate userIDs Exist                             #
##########################################################################
no_dup_user_id(){

    # Refer to CIS-CAT Report for list of duplicate UID/GID.
    
    echo "" > /dev/null

}

##########################################################################
#   11.3 - Force Permissions on root's Home Directory to be 0700         #
##########################################################################
set_root_perms(){
    
    chown root:root /root
    chmod 0700 /root

}

##########################################################################
#   11.4 - Utilize PAM to Enforce userID Password Complexity             #
##########################################################################
set_complex_passwd(){

    # dcredit is number of numerals/digits required (1)
    # lcredit is number of lower-case characters required (1)
    # ocredit is number of other/special/punctuation characters required (1)
    # ucredit is number of upper-case characters required (1)
    # minlen is the minimum password length required (8)
    
    FILE="/etc/pam.d/system-auth"
    
    if [ -e $FILE ]; then
    
        /bin/cp -pf ${FILE} ${FILE}.tmp
        
        awk '( $1 == "password" && $2 == "requisite" && $3 == "pam_cracklib.so" ) \
        { print $0 " dcredit=-1 lcredit=-1 ocredit=-1 ucredit=-1 minlen=8"; \
        next }; \
        { print }' ${FILE}.tmp > ${FILE}
        
        chown root:root ${FILE}
        chmod 0644 ${FILE}
        
        rm ${FILE}.tmp
        
    fi

}

##########################################################################
#   11.5 - Perms on man/doc Pages Prevent Modification by Unprivileged   #
##########################################################################
set_man_doc_perms(){

    if [ -e /usr/share/doc ]; then
        chown -R root:root /usr/share/doc
        chmod -R 644 /usr/share/doc
    fi
    
    if [ -e /usr/local/share/doc ]; then
        chown -R root:root /usr/local/share/doc
        chmod -R 644 /usr/local/share/doc  
    fi
    
    if [ -e /usr/share/man ]; then
        chown -R root:root /usr/share/man
        chmod -R 644 /usr/share/man
    fi
    
    if [ -e /usr/local/share/man ]; then
        chown -R root:root /usr/local/share/man
        chmod -R 644 /usr/local/share/man
    fi

}

##########################################################################
#   11.6 - Reboot                                                        #
##########################################################################
reboot_sys(){

    # System should be rebooted to ensure hardening settings are loaded.
    # Perform a manual reboot if possible.

        # Execute the following:

            # touch /.autorelabel
            # init 6
            
    echo "" > /dev/null

}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 11.0 - Misc Odds and Ends                                #
#                                                                        #
##########################################################################

##########################################################################
#   11.1 - Configure and Enable the auditd and sysstat Services          #
##########################################################################

# This item is applicable to 32-bit systems only.
# Comment out this function for 64-bit systems.

#enable_auditd_sysstat

##########################################################################
#   11.2 - Verify No Duplicate userIDs Exist                             #
##########################################################################

no_dup_user_id

##########################################################################
#   11.3 - Force Permissions on root's Home Directory to be 0700         #
##########################################################################

set_root_perms

##########################################################################
#   11.4 - Utilize PAM to Enforce userID Password Complexity             #
##########################################################################

set_complex_passwd

##########################################################################
#   11.5 - Perms on man/doc Pages Prevent Modification by Unprivileged   #
##########################################################################

set_man_doc_perms

##########################################################################
#   11.6 - Reboot                                                        #
##########################################################################

reboot_sys

#---------- END  CONFIGURATION ----------#

#----------   END SECTION 11   ----------#

#END
