#!/bin/sh

#
# harden_06_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: HP Consulting - Security & Risk Management, Jack Maynard       #
# Created: May 10, 2010 - HP version 1.0                                 #
#                                                                        #
# RHEL5 Hardening Script Section 6.0 - Logging                           #
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
#       RHEL5 Benchmark Section 6.0                                      #
#       Logging                                                          #
#                                                                        #
##########################################################################

##########################################################################
#       6.1 - Capture Messages Sent To Syslog AUTHPRIV Facility          #
##########################################################################
log_authpriv(){

    if [ `grep -v '^#' /etc/syslog.conf | grep -v authpriv\.none | grep -c \
            'authpriv'` -eq 0 ]; then
        echo -e "authpriv.*\t\t\t\t/var/log/secure" >> /etc/syslog.conf
    fi

    # Add record for 'auth.*', too, placing it after the authpriv record

    if [ `grep -v '^#' /etc/syslog.conf | grep -c 'auth.\*'` -eq 0 ]; then
        ed /etc/syslog.conf > /dev/null <<END_SCRIPT
1
/^authpriv
a
auth.* /var/log/messages
.
w
q
END_SCRIPT

    fi

    chown root:root /etc/syslog.conf

    # Original/default permissions are 0644.

    chmod 0600 /etc/syslog.conf

    # Create the log file if it doesn't already exist.

    touch /var/log/secure

    chown root:root /var/log/secure
    chmod 0600 /var/log/secure

    # Restart syslog service to immediately implement the latest configuration.

    service syslog stop > /dev/null
    service syslog start > /dev/null
}


##########################################################################
#   6.2 - Turn On Additional Logging For FTP Daemon                      #
##########################################################################
log_ftp(){

  FILE=""

    if [ -f /etc/vsftpd.conf ]; then
        FILE="/etc/vsftpd.conf"
    else
        FILE="/etc/vsftpd/vsftpd.conf"
    fi

    if [ -f $FILE ]; then
    
        cp -p ${FILE} ${FILE}.tmp
        
        awk '/^#?xferlog_std_format/ \
            { print "xferlog_std_format=NO"; next };
        /^#?log_ftp_protocol/ \
            { print "log_ftp_protocol=YES"; next };
        { print }' ${FILE}.tmp > ${FILE}
        
        rm ${FILE}.tmp

        if [ `egrep -c log_ftp_protocol ${FILE}` == 0 ]; then
            echo "log_ftp_protocol=YES" >> ${FILE}
        fi

    chown root:root $FILE
    chmod 0600 $FILE

    fi
}

##########################################################################
#   6.3 - Confirm Permissions On System Log Files                        #
##########################################################################
confirm_syslog_perms(){

    cd /var/log

    # Ensure the btmp log file for 'lastb' is in place,
    # and with proper permissions.

    touch /var/log/btmp

    chown root:root /var/log/btmp
    chmod 0600 /var/log/btmp
    
    # Utilizing recursiveness.  Harmless when applied to a single file.

    # Log Perms - Part 1
    
    for LOG in boot.log* cron* dmesg ksyms* httpd/* maillog* messages* news/* pgsql rpmpkgs* samba/* sa/* scrollkeeper.log secure* spooler* squid/* vbox/* wtmp; do
    
        if [ -e $LOG ]; then
            chmod -R o-rwx ${LOG}
        fi    
    done

    # Log Perms - Part 2

    for LOG in boot.log* cron* maillog* messages* pgsql secure* spooler* squid/* sa/*; do
    
        if [ -e $LOG ]; then
            chmod -R o-rx ${LOG}
        fi  
    done

    # Log Perms - Part 3

    for LOG in boot.log* cron* dmesg httpd/* ksyms* maillog* messages* pgsql rpmpkgs* samba/* sa/* scrollkeeper.log secure* spooler*; do
  
        if [ -e $LOG ]; then
            chmod -R g-w ${LOG}
        fi 
    done

    # Log Perms - Part 4

    for LOG in boot.log* cron* maillog* messages* pgsql secure* spooler*; do
    
        if [ -e $LOG ]; then
            chmod -R g-rx ${LOG}
        fi
    done

    # Log Perms - Part 5

    for LOG in gdm/ httpd/ news/ samba/ squid/ sa/ vbox/; do
  
        if [ -e $LOG ]; then
            chmod -R o-w ${LOG}
        fi
    done

    # Log Perms - Part 6

    for LOG in httpd/ samba/ squid/ sa/; do
  
        if [ -e $LOG ]; then
            chmod -R o-rx ${LOG}
        fi
    done

    # Log Perms - Part 7

    for LOG in gdm/ httpd/ news/ samba/ squid/ sa/ vbox/; do
  
        if [ -e $LOG ]; then
            chmod -R g-w ${LOG}
        fi
    done

    # Log Perms - Part 8

    for LOG in httpd/ samba/ sa/; do
  
        if [ -e $LOG ]; then
            chmod -R g-rx ${LOG}
        fi
    done
   
   # Log Perms - Part 9

    for LOG in kernel syslog loginlog; do
      
        if [ -e $LOG ]; then
            chmod -R u-x ${LOG}
        fi
     done

    # Log Perms - Part 10

    # Removing group write permissions to btmp and wtmp

    chgrp utmp btmp
    chmod g-w btmp
    
    chgrp utmp wtmp
    chmod g-w wtmp

    # Fixing "/etc/rc.d/rc.sysinit", as it unsecures permissions for wtmp.
    
    FILE="/etc/rc.d/rc.sysinit"
    
    if [ -f $FILE ]; then
    
    cp -p ${FILE} ${FILE}.tmp

    awk '( $1 == "chmod" && $2 == "0664" && $3 == "/var/run/utmp" && $4 == "/var/log/wtmp" ) {
        print "chmod 0600 /var/run/utmp /var/log/wtmp"; next };
        ( $1 == "chmod" && $2 == "0664" && $3 == "/var/run/utmpx" && $4 == "/var/log/wtmpx" ) {
        print " chmod 0600 /var/run/utmpx /var/log/wtmpx"; next };
        { print }' ${FILE}.tmp > ${FILE}
        
    rm ${FILE}.tmp

    chown root:root ${FILE}
    chmod 0700 ${FILE}
    
    fi

    # Log Perms - Part 11

    [ -e news ]    && chown -R news:news news
    [ -e pgsql ]   && chown postgres:postgres pgsql
    [ -e squid ]   && chown -R squid:squid squid
    [ -e lastlog ] && chmod 0600 lastlog
    [ -e wtmp ]    && chgrp utmp wtmp
    
    # Set /var/log ownership and permission
    
    chown root:root .

}

##########################################################################
#   6.4 Configure syslogd to Send Logs to a Remote LogHost               #
##########################################################################
remote_syslog(){

LOGHOST="localhost"

printf "# Following 6 lines added per CIS RHEL Benchmark\n\
kern.warning;*.err;authpriv.none\t@$LOGHOST\n\
*.info;mail.none;authpriv.none;cron.none\t@$LOGHOST\n\
*.emerg\t\t@$LOGHOST\n\
auth.*\t\t@$LOGHOST\n\
authpriv.*\t@$LOGHOST\n\
local7.*\t@$LOGHOST\n" >> /etc/syslog.conf

chown root:root /etc/syslog.conf
chmod 0600 /etc/syslog.conf
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 6.0 - Logging                                            #
#                                                                        #
##########################################################################

##########################################################################
#   6.1 Capture Messages Sent To Syslog AUTHPRIV Facility                #
##########################################################################

log_authpriv

##########################################################################
#   6.2 Turn On Additional Logging For FTP Daemon                        #
##########################################################################

log_ftp

##########################################################################
#   6.3 Confirm Permission On System Log Files                           #
##########################################################################

confirm_syslog_perms

##########################################################################
#   6.4 Configure syslogd to Send Logs to a Remote LogHost              #
##########################################################################

# You MUST configure remote syslog host variable $LOGHOST in function 6.4
remote_syslog

#---------- END  CONFIGURATION ----------#

#----------    END SECTION 6   ----------#

#END