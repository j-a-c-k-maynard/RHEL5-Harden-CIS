#!/bin/sh

#
# harden_07_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: HP Consulting - Security & Risk Management, Jack Maynard       #
# Created: May 10, 2010 - HP version 1.0                                 #
#                                                                        #
# RHEL5 Hardening Script Section 7.0 - File/Directory Permissions/Access #
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
#       RHEL5 Benchmark Section 7.0                                      #
#       File/Directory Permissions/Access                                #
#                                                                        #
##########################################################################

##########################################################################
#   7.1 - Add 'nodev' Option To Appropriate Partitions In /etc/fstab     #
##########################################################################
add_nodev_partitions(){

    awk '( $3 ~ /^ext[23]$/ && $2 != "/" ) { $4 = $4 ",nodev" }; \
        { printf "%-26s %-22s %-8s %-16s %-1s %-1s\n",$1,$2,$3,$4,$5,$6 }' \
            /etc/fstab > /tmp/fstab.tmp

    cp -f /tmp/fstab.tmp /etc/fstab
    rm -f /tmp/fstab.tmp
    
    chown -f root:root /etc/fstab
    chmod -f 0644 /etc/fstab
    
}

##########################################################################
#   7.2 - Add 'nosuid' 'nodev' Option For Removable Media In /etc/fstab  #
##########################################################################
add_nosuid_nodev_removable_media(){

# Part 1

    # Additional devices this section 'might' consider could be a DVD or cd recorder

    awk '( $2 ~ /^\/m.*\/(floppy|cdrom|corder)$/ ) && ( $4 !~ /,nodev,nosuid/ ) \
        { $4 = $4 ",nodev,nosuid" }; \
        { printf "%-26s%-22s%-8s%-16s %-1s %-1s\n",$1,$2,$3,$4,$5,$6 }' \
            /etc/fstab > /tmp/fstab.tmp

    cp -f /tmp/fstab.tmp /etc/fstab

    chown -f root:root /etc/fstab
    chmod -f 0644 /etc/fstab

# Part 2

    fdiPATH='unknown'

    if [ -e /usr/share/hal/fdi/95userpolicy ]; then

        # Apply this to RHEL AS4 system
        fdiPATH="/usr/share/hal/fdi/95userpolicy"

    else

        if [ -e /usr/share/hal/fdi/policy/20thirdparty ]; then

            # apply this for RHEL5
            fdiPATH="/usr/share/hal/fdi/policy/20thirdparty"
        fi
    fi

    if [ "$fdiPATH" == 'unknown' ]; then

        echo > /dev/null

    else

cat <<END_SCRIPT >> $fdiPATH/floppycdrom.fdi
<?xml version="1.0" encoding="ISO-8859-1"?> <!-- -*- SGML -*- -->
<deviceinfo version="0.2">
<!-- Default policies merged onto computer root object -->
<device>
<match key="info.udi" string="/org/freedesktop/Hal/devices/computer">
<merge key="storage.policy.default.mount_option.nodev" type="bool">true</merge>
<merge key="storage.policy.default.mount_option.nosuid" type="bool">true</merge>
</match>
</device>
</deviceinfo>
END_SCRIPT

    chown -f root:root $fdiPATH/floppycdrom.fdi
    chmod -f 0640 $fdiPATH/floppycdrom.fdi

    fi
}

##########################################################################
#   7.3 - Disable User-Mounted Removable File Systems                    #
##########################################################################
disable_user_mount_removable_filesys(){

    CONS_PERM_FILE="/etc/security/console.perms"
    DEF_FILE="/etc/security/console.perms.d/50-default.perms"

    # If the test below passes, the 2nd file is changed, not the first.
    # Need to protect both.

    test -f ${DEF_FILE} && CONS_PERM_FILE=${DEF_FILE}

    # Each entry listed below will NOT be commented out in the
    # "console.perms" file.  The remaining entries in that file WILL
    # be commented out and thus disabled post-reboot.  Further, "memstick"
    # and "diskonkey" were not part of the original CIS specification to be
    # left alone, but have been included to tailor the hardened build for
    # usage of normal system USB requirements (such as keyboards and mice).

    cp ${CONS_PERM_FILE} ${CONS_PERM_FILE}.tmp
    
    awk '( $1 == "<console>" ) && \
    ( $3 !~ /sound|fb|kbd|joystick|v4l|mainboard|gpm|scanner|memstick|diskonkey/ ) \
        { $1 = "#<console>" }; { print }' ${CONS_PERM_FILE}.tmp > ${CONS_PERM_FILE}

    chown -f root:root ${CONS_PERM_FILE}
    chmod -f 0600 ${CONS_PERM_FILE}
    
    rm ${CONS_PERM_FILE}.tmp
    
}

##########################################################################
#   7.4 - Verify passwd, shadow, and group File Permissions              #
##########################################################################
verify_passwd_shadow_group_perms(){

    for FILE in /etc/group /etc/gshadow /etc/passwd /etc/shadow;

    do

        if [ -e $FILE ]; then
            chown root:root ${FILE}
        fi

    done

    for FILE in /etc/group /etc/passwd;

    do

        if [ -e $FILE ]; then
            chmod 0644 ${FILE}
            ls -l ${FILE}
        fi

    done

    for FILE in /etc/gshadow /etc/shadow;

    do

        if [ -e $FILE ]; then
          chmod 0400 ${FILE}
          ls -l ${FILE}
        fi

    done

}

##########################################################################
#   7.5 - Ensure World-Writable Directories Have Their Sticky Bit Set    #
##########################################################################
find_world_write_sticky(){

    for PART in `awk '($3 ~ "ext2|ext3") { print $2 }' /etc/fstab`; do 
    
        find $PART -xdev -type d -perm -0002 -a ! -perm -1000 -ls \
        | while read DIR; do
        
            chmod o+t $DIR
            echo $DIR
            
            done
        
        done

}

##########################################################################
#   7.6 - Find Unauthorized World-Writable Files                         #
##########################################################################
find_unauth_world_write(){

    for PART in $( grep -v '^#' /etc/fstab | awk '( $3 ~ "ext[23]" ) \
    { print $2 }' ); do

        find $PART -xdev -type f -perm -0002 -a ! -perm -1000 \
        -print | while read FILE; do
        
            chmod o-w $FILE
            
        done

    done

}

##########################################################################
#   7.7 - Find Unauthorized SUID/SGID System Executables                 #
##########################################################################
find_unauth_suid_sgid(){

    for PART in $( grep -v '^#' /etc/fstab | \
    awk '($3 ~ "ext[23]" ) { print $2 }' ); do
    
    find $PART -xdev -perm -04000 -o -perm -02000 -print | sort \
    | while read FILE; do
    
        if [[ ! $(grep $FILE ./include/authorized-suid-sgid.txt) ]]; then
            echo $FILE
        fi
        
        done
        
    done

}

##########################################################################
#   7.8 - Find All Unowned Directories and Files                         #
##########################################################################
find_unowned_files(){

    # Refer to CIS-CAT Report for a list of unowned directories / files.
    
        echo "" > /dev/null
        
}

##########################################################################
#   7.9 - Disable USB Devices                                            #
##########################################################################
disable_usb(){

    DEF_KERN=$( grubby --default-kernel)
    grubby --update-kernel=$DEF_KERN --args="nousb"
    
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Section 7.0 - File/Directory Permissions/Access                  #
#                                                                        #
##########################################################################

##########################################################################
#   7.1 - Add 'nodev' Option To Appropriate Partitions In /etc/fstab     #
##########################################################################

add_nodev_partitions

##########################################################################
#   7.2 - Add 'nosuid' 'nodev' Option For Removable Media In /etc/fstab  #
##########################################################################

add_nosuid_nodev_removable_media

##########################################################################
#   7.3 - Disable User-Mounted Removable File Systems                    #
##########################################################################

disable_user_mount_removable_filesys

##########################################################################
#   7.4 - Verify passwd, shadow, and group File Permissions              #
##########################################################################

verify_passwd_shadow_group_perms

##########################################################################
#   7.5 - Ensure World-Writable Directories Have Their Sticky Bit Set    #
##########################################################################

find_world_write_sticky

##########################################################################
#   7.6 - Find Unauthorized World-writable Files                         #
##########################################################################

find_unauth_world_write

##########################################################################
#   7.7 - Find Unauthorized SUID/SGID System Executables                 #
##########################################################################

find_unauth_suid_sgid

##########################################################################
#   7.8 - Find All Unowned Directories and Files                         #
##########################################################################

find_unowned_files

##########################################################################
#   7.9 - Disable USB Devices                                            #
##########################################################################

#disable_usb

#---------- END  CONFIGURATION ----------#

#----------    END SECTION 7   ----------#

#END
