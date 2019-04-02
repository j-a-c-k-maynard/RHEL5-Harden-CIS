#!/bin/sh

#
# harden_08_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RHEL5 Hardening Script Section 8.0 - System Access, Authentication,    #
# and Authorization                                                      #
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
#       RHEL5 Benchmark Section 8.0                                      #
#       System Access, Authentication, and Authorization                 #
#                                                                        #
##########################################################################

##########################################################################
#   8.1 - Remove .rhosts Support In PAM Configuration Files              #
##########################################################################
remove_rhosts_pam(){

   cd /etc/pam.d

    for FILE in `find . -type f -exec grep -l rhosts_auth {} \;`; 
    
    do
        grep -v rhosts_auth $FILE > /tmp/${FILE}.tmp
        /bin/cp -f /tmp/${FILE}.tmp $FILE

        chown root:root /etc/pam.d/*
        chmod 0644 /etc/pam.d/*
        
        rm /tmp/${FILE}.tmp
    done

}

##########################################################################
#   8.2 - Create ftpusers Files                                          #
##########################################################################
create_ftpusers(){

    if [ -f /etc/ftpaccess ];

    then

        for NAME in `cut -d: -f1 /etc/passwd`;

        do

            if [ `id -u $NAME` -lt 500 ]; then

                echo $NAME >> /etc/ftpusers

            fi

        done

        chown root:root /etc/ftpusers
        chmod 0600 /etc/ftpusers

        VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
        ALT_CONF="/etc/vsftpd/vsftpd.conf"

        test -f $ALT_CONF && VSFTP_CONF=$ALT_CONF

        if [ -e $VSFTP_CONF ] && ! grep -q "^userlist_deny=NO" $VSFTP_CONF;

        then

            /bin/cp -fp /etc/ftpusers /etc/vsftpd.ftpusers

            chown root:root /etc/vsftpd/vsftpd.conf
            chgrp 0600 /etc/vsftpd/vsftpd.conf

        fi

    fi
}

##########################################################################
#   8.3 - Prevent X Server From Listening On Port 6000/tcp               #
##########################################################################
prevent_xserver_6000tcp(){

    FILE="/etc/X11/xdm/Xservers"

    if [ -e $FILE ]; then

        cp ${FILE} ${FILE}.tmp
        
        cd /etc/X11/xdm

        awk '( $1 !~ /^#/ && $3 == "/usr/X11R6/bin/X" ) { $3 = $3 " -nolisten tcp" };
        { print }' ${FILE}.tmp > ${FILE}

        chown root:root ${FILE}
        chmod 0444 ${FILE}
        
        rm ${FILE}.tmp   

    else

    mkdir -p /etc/X11/xdm
    cd /etc/X11/xdm

    echo "/usr/X11R6/bin/X -nolisten tcp" > ${FILE}

    chown root:root ${FILE}
    chmod 0444 ${FILE}

    fi

    if [ -d /etc/X11/xinit ];

    then

        cd /etc/X11/xinit

        if [ -e xserverrc ];

        then
        
            cp xserverrc xserverrc.tmp

            awk '/X/ && !/^#/ { print $0 " :0 -nolisten tcp \$@"; next }; \
            { print }' xserverrc.tmp > xserverrc
            
            rm xserverrc.tmp

        else

        cat <<END_SCRIPT > xserverrc
#!/bin/bash
exec X :0 -nolisten tcp \$@
END_SCRIPT

        fi

        chown root:root xserverrc
        chmod 0755 xserverrc

    fi
    
}

##########################################################################
#   8.4 - Restrict at/cron To Authorized Users                           #
##########################################################################
restrict_at_cron(){

    # With x.allow only users listed can use 'at' or 'cron'
    # {where 'x' indicates either 'at' or 'cron'}
    # Without x.allow then x.deny is checked, members of x.deny are excluded
    # Without either (x.allow and x.deny), then only root can use 'at' and 'cron'
    # At a minimum x.allow should exist and list root

    rm -f /etc/at.deny /etc/cron.deny

    echo root > /etc/at.allow
    echo root > /etc/cron.allow

    chown root:root /etc/at.allow /etc/cron.allow
    chmod 0400 /etc/at.allow /etc/cron.allow
    
}

##########################################################################
#   8.5 - Restrict Permissions On crontab Files                          #
##########################################################################
restrict_crontab_perms(){

    if [ -e /etc/crontab ]; then
        
        chown root:root /etc/crontab
        chmod 0400 /etc/crontab
        
        echo "ls -l /etc/crontab"
        ls -l /etc/crontab
        echo ""
    
    fi
    
    if [ -e /var/spool/cron ]; then

        chown -R root:root /var/spool/cron
        chmod -R go-rwx /var/spool/cron

        echo "ls -l /var/spool/cron"
        ls -l /var/spool/cron
        echo ""
        
    fi
    
    cd /etc/
    
    ls | grep cron | xargs chown -R root:root
    ls | grep cron | xargs chmod -R go-rwx 
    
}

##########################################################################
#   8.6 - Restrict Root Logins To System Console                         #
##########################################################################
restrict_root_logins(){

# Part 1

    echo console > /etc/securetty
    echo tty0   >> /etc/securetty
    echo tty1   >> /etc/securetty
    echo tty2   >> /etc/securetty
    echo tty3   >> /etc/securetty
    echo ttys0  >> /etc/securetty
    echo ttys1  >> /etc/securetty
    echo ttys2  >> /etc/securetty
    echo ttys3  >> /etc/securetty

    # These are acceptable for the GUI and runlevel 3, when trimmed down to 6

    for i in `seq 1 6`; do

        echo vc/$i >> /etc/securetty

    done

    chown root:root /etc/securetty
    chmod 0400 /etc/securetty

# Part 2

    # Second modification of gdm.conf, if it exists.

    if [ -e /etc/X11/gdm/gdm.conf ]; then

    #### There is another file to consider: "/etc/X11/gdm/gdm.conf"
    # "AllowRoot=true" should be set to false to prevent root from logging in to the gdm GUI.
    # "AllowRemoteRoot=true" should be set to false to prevent root logins from remote systems.
    # Doing this change is supportive of logging in as a regular user and using 'su' to get to root.
    # Before allowing a reboot, ensure at least one account is created for a SysAdmin type.

    cd /etc/X11/gdm

    /bin/cp -pf gdm.conf $TEMP_DIR/gdm.conf.tmp

    sed -e 's/AllowRoot=true/AllowRoot=false/' \
    -e 's/AllowRemoteRoot=true/AllowRemoteRoot=false/' \
    -e 's/^#Use24Clock=false/Use24Clock=true/'
    $TEMP_DIR/gdm.conf.tmp > gdm.conf

    chown root:root gdm.conf
    chmod 0644 gdm.conf

    fi

# Part 3

    # The following is only required when a serial console is used for this server.
    # Either of these would be added manually post-baseline compliance, depending
    # on the COM port the serial cable is physically attached to.

    # echo ttyS0 >> /etc/securetty
    # echo ttyS1 >> /etc/securetty
}

##########################################################################
#   8.7 - Set GRUB Password                                              #
##########################################################################
set_grub_passwd(){

    # Setting grub password is a manual action, to set:

    # 1. Add this line to /etc/grub.conf before the first uncommented line:

        # password <password>
        # Replace <password> with an md5 encrypted password.

    # 2. Execute the following commands as root:

        # chown root:root /boot/grub/grub.conf
        # chmod 0600 /boot/grub/grub.conf
        
    echo "" > /dev/null
    
}

##########################################################################
#   8.8 - Require Authentication For Single-User Mode                    #
##########################################################################
require_single_user_auth(){

    cd /etc

    if [ "`grep -l sulogin inittab`" = "" ];

    then

        awk '{ print }; /^id:[0123456sS]:initdefault:/ \
        { print "~~:S:wait:/sbin/sulogin" }' \
        inittab > $TEMP_DIR/inittab.tmp

        /bin/cp -pf $TEMP_DIR/inittab.tmp inittab

        chown root:root inittab
        chmod 0600 inittab

    fi
}

##########################################################################
#   8.9 - Restrict NFS Client Requests To Privileged Ports               #
##########################################################################
restrict_nfs_clients(){

    if [ `wc -c /etc/exports | cut -d' ' -f1` == 0 ];

    then

        echo > /dev/null

    else

        perl -i.orig -pe 'next if (/^\s*#/ || /^\s*$/);
            ($res, @hst) = split(" ");
            foreach $ent (@hst) {
            undef(%set);
            ($optlist) = $ent =~ /\((.*?)\)/;
            foreach $opt (split(/,/, $optlist)) {
            $set{$opt} = 1;
            }
            delete($set{"insecure"});
            $set{"secure"} = 1;
            $ent =~ s/\(.*?\)//;
            $ent .= "(" . join(",", keys(%set)) . ")";
            }
            $hst[0] = "(secure)" unless (@hst);
            $_ = "$res\t" . join(" ", @hst) . "\n";' /etc/exports
    fi

    chown root:root /etc/exports
    chmod 0644 /etc/exports
}

##########################################################################
#   8.10 - Only Enable syslog To Accept Messages, If Absolutely Necessary#
##########################################################################
enable_syslog(){

cat <<END_SCRIPT > /tmp/syslog.tmp   
#!/bin/bash
#
# syslog        Starts syslogd/klogd.
#
#
# chkconfig: 2345 12 88
# description: Syslog is the facility by which many daemons use to log \
# messages to various system log files.  It is a good idea to always \
# run syslog.
### BEGIN INIT INFO
# Provides: $syslog
### END INIT INFO

# Source function library.
. /etc/init.d/functions

RETVAL=0

start() {
	[ -x /sbin/syslogd ] || exit 5
	[ -x /sbin/klogd ] || exit 5

	# Source config
	if [ -f /etc/sysconfig/syslog ] ; then
		. /etc/sysconfig/syslog
	else
	
	        # SYSLOGD_OPTIONS var modified per CIS RHEL5 Benchmark
		SYSLOGD_OPTIONS="-m 0 -l loghost -r -s rim.com"
		KLOGD_OPTIONS="-2"
	fi

	if [ -z "$SYSLOG_UMASK" ] ; then
	      SYSLOG_UMASK=077;
	fi
	umask $SYSLOG_UMASK

 	echo -n $"Starting system logger: "
	daemon syslogd $SYSLOGD_OPTIONS
	RETVAL=$?
	echo
	echo -n $"Starting kernel logger: "
	daemon klogd $KLOGD_OPTIONS
	echo
	[ $RETVAL -eq 0 ] && touch /var/lock/subsys/syslog
	return $RETVAL
}	
stop() {
	echo -n $"Shutting down kernel logger: "
	killproc klogd
	echo
	echo -n $"Shutting down system logger: "
	killproc syslogd
	RETVAL=$?
	echo
	[ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/syslog
	return $RETVAL
}
rhstatus() {
	status syslogd
	status klogd
}
restart() {
	stop
	start
}	
reload()  {
    RETVAL=1
    syslog=`cat /var/run/syslogd.pid 2>/dev/null`
    echo -n "Reloading syslogd..."
    if [ -n "${syslog}" ] && [ -e /proc/"${syslog}" ]; then
	kill -HUP "$syslog";
	RETVAL=$?
    fi
    if [ $RETVAL -ne 0 ]; then
	failure
    else
	success
    fi
    echo
    RETVAL=1
    echo -n "Reloading klogd..."
    klog=`cat /var/run/klogd.pid 2>/dev/null`
    if [ -n "${klog}" ] && [ -e /proc/"${klog}" ]; then
	kill -USR2 "$klog";
        RETVAL=$?
    fi
    if [ $RETVAL -ne 0 ]; then
	failure
    else
	success
    fi
    echo    
    return $RETVAL
}
case "$1" in
  start)
  	start
	;;
  stop)
  	stop
	;;
  status)
  	rhstatus
	;;
  restart)
  	restart
	;;
  reload)
	reload
	;;
  condrestart)
  	[ -f /var/lock/subsys/syslog ] && restart || :
	;;
  *)
	echo $"Usage: $0 {start|stop|status|restart|condrestart}"
	exit 2
esac

exit $?
END_SCRIPT
     
    cp /tmp/syslog.tmp /etc/init.d/syslog
    rm /tmp/syslog.tmp

    chown root:root /etc/init.d/syslog
    chmod 755 /etc/init.d/syslog
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 8.0 - System Access, Authentication, and Authorization   #
#                                                                        #
##########################################################################

##########################################################################
#   8.1 - Remove .rhosts Support In PAM Configuration Files              #
##########################################################################

remove_rhosts_pam

##########################################################################
#   8.2 - Create ftpusers Files                                          #
##########################################################################

create_ftpusers

##########################################################################
#   8.3 - Prevent X Server From Listening On Port 6000/tcp               #
##########################################################################

prevent_xserver_6000tcp

##########################################################################
#   8.4 - Restrict at/cron To Authorized Users                           #
##########################################################################

restrict_at_cron

##########################################################################
#   8.5 - Restrict Permissions On crontab Files                          #
##########################################################################

restrict_crontab_perms

##########################################################################
#   8.6 - Restrict Root Logins To System Console                         #
##########################################################################

restrict_root_logins

##########################################################################
#   8.7 - Set GRUB Password                                              #
##########################################################################

set_grub_passwd

##########################################################################
#   8.8 - Require Authentication For Single-User Mode                    #
##########################################################################

require_single_user_auth

##########################################################################
#   8.9 - Restrict NFS Client Requests To Privileged Ports               #
##########################################################################

restrict_nfs_clients

##########################################################################
#   8.10 - Only Enable syslog To Accept Messages, If Absolutely Necessary#
##########################################################################

# Make sure you edit the domain as required in function 8.10 above.
enable_syslog

#---------- END  CONFIGURATION ----------#

#----------    END SECTION 8   ----------#

#END
