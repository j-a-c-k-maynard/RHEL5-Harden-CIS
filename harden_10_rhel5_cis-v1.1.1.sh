#!/bin/sh

#
# harden_10_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: HP Consulting - Security & Risk Management, Jack Maynard       #
# Created: May 10, 2010 - HP version 1.0                                 #
#                                                                        #
# RHEL5 Hardening Script Section 10.0 - Warning Banners                  #
# Scripted to Center for Internet Security (CIS) RHEL5 Benchmark v1.1.1  #
# www.cisecurity.org                                                     #
##########################################################################

# Variable Declarations

# Redirect stdout and stderr to /dev/null, this helps reduce screen noise.
# Change /dev/null to a real file for debugging purposes.

    STDOUT_STDERR="/dev/null"
    exec &>${STDOUT_STDERR}

# Set current working directory

    cwd=`dirname $0`
    cwd=`(cd $cwd; pwd)`

##########################################################################
#                                                                        #
#       RHEL5 Benchmark Section 10.0                                     #
#       Warning Banners                                                  #
#                                                                        #
##########################################################################

##########################################################################
#   10.1 - Create Warnings For Network And Physical Access Services      #
##########################################################################
create_term_banner(){

    cat $cwd/include/issue.txt > /etc/issue
    cat $cwd/include/motd.txt  > /etc/motd

    cp -pf /etc/issue /etc/issue.net

    chown root:root /etc/issue /etc/issue.net /etc/motd
    chmod 644 /etc/issue /etc/issue.net /etc/motd

}

##########################################################################
#   10.2 - Create Warnings for GUI-Based Logins                          #
##########################################################################
create_gui_banner(){

    FILE="/etc/X11/xdm/Xresources"

    if [ -e $FILE ]; then

        cp ${FILE} ${FILE}.tmp

        awk '/xlogin\*greeting:/ \
        { print "xlogin\*greeting: Authorized uses only!"; next };
        { print }' ${FILE}.tmp > ${FILE}

        chown root:root ${FILE}
        chmod 644 ${FILE}
        
    fi
    
    FILE2="/etc/X11/xdm/kdmrc"

    if [ -e $FILE2 ]; then

        cp ${FILE2} ${FILE2}.tmp

        awk '/GreetString=/ \
        { print "GreetString=Authorized uses only!"; next };
        { print }' ${FILE2}.tmp > ${FILE2}

        chown root:root ${FILE2}
        chmod 644 ${FILE2}

    fi
    
    FILE3="/etc/X11/gdm/gdm.conf"

    if [ -e $FILE3 ]; then

        cp -pf ${FILE3} ${FILE3}.tmp

        awk '/^Greeter=/ && /gdmgreeter/ \
        { printf("#%s\n", $0); next };
        /^#Greeter=/ && /gdmlogin/ \
        { $1 = "Greeter=gdmlogin" }; /Welcome=/ \
        { print "Welcome=Authorized uses only!"; next };
        { print }' ${FILE3}.tmp > ${FILE3}
        
        rm -f ${FILE3}.tmp

        chown root:root ${FILE3}
        chmod 644 ${FILE3}

    fi

# This FORCES the user, upon successfully passing thru a
# credentialed GUI login to positively acknowledge Consent-to-Use.

    FILE4="/etc/gdm/PreSession/Default"

    if [ -e $FILE4 ]; then
    
ed /etc/gdm/PreSession/Default > /dev/null <<END_SCRIPT
1
/^SESSREG=
a
/usr/bin/xmessage -center -buttons " I acknowledge and consent to monitoring \
":2," Cancel Login ":3 -file /etc/issue
egxit="\$?"
if [ \$egxit != 2 ]; then
    # Immediately FORCE logout by killing the 'X' session process
    echo "Consent-To-Use: User (\$LOGNAME) cancelled login (\`date\`)." \
        >> /var/log/messages
        kill -9 \`ps -ef |grep /usr/bin/X |grep -v grep | tr -s ' ' | cut -d' ' -f2\`
fi
.
w
q
END_SCRIPT

    chown root:root /etc/gdm/PreSession/Default
    chmod 0755 /etc/gdm/PreSession/Default

    fi

}

##########################################################################
#   10.3 - Create Authorized Only Banners For vsftpd, proftpd            #
##########################################################################
create_ftp_banner(){

    cd /etc

    if [ -d vsftpd ]; then

        cd vsftpd
    fi

    if [ -e vsftpd.conf ]; then

        echo "ftpd_banner=Authorized users only. All activity may be monitored and reported." >> vsftpd.conf

    fi

    if [ -e proftpd.conf ]; then

        echo -e "DisplayConnect\t\t/etc/issue.net" >> proftpd.conf
        echo -e "DisplayLogin\t\t/etc/motd" >> proftpd.conf
    fi
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 10.0 - Warning Banners                                   #
#                                                                        #
##########################################################################

##########################################################################
#   10.1 - Create Warnings For Network And Physical Access Services      #
##########################################################################

create_term_banner

##########################################################################
#   10.2 - Create Warnings for GUI-Based Logins                          #
##########################################################################

create_gui_banner

##########################################################################
#    10.3 - Create Authorized Only Banners For vsftpd, proftpd           #
##########################################################################

create_ftp_banner

#---------- END  CONFIGURATION ----------#

#----------   END SECTION 10   ----------#

#END
