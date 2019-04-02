#!/bin/sh

#
# do-harden_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RedHat Enterprise Linux 5 (RHEL5)  Security Hardening CONTROL Script   #
# This script launches all other CIS Benchmark Section hardening scripts.#
# Scripted to Center for Internet Security (CIS) RHEL5 Benchmark v1.1.1  #
# www.cisecurity.org                                                     #
##########################################################################

# Variable Declarations

NODE=`uname -n`
OS=`uname -s`
OSREV=`uname -r`
IPADDR="$(ip addr show dev eth0 |grep "inet " | cut -d" " -f6)"
DATE=`date '+%Y%m%d'` 
TIMESTAMP=`date '+%Y%m%d_%H%M%S'`

export NODE OS OSREV IPADDR DATE TIMESTAMP

# Redirect stderr to /dev/null

    ERR_FILE="/dev/null"
    exec 2>>${ERR_FILE}

# Provide A Warning Disclaimer

clear
cat << EOF

##########################################################################
#                            *** WARNING ***                             #
##########################################################################
#  Running this script will harden the system to CIS Benchmark settings. #
#  It will change system configuration and will affect system operation  #
#                                                                        #
#         ONLY RUN THIS SCRIPT IF YOU KNOW WHAT YOU ARE DOING!           #
##########################################################################

The system you are about to harden is:
EOF

# Send the system name and the date hardening scripts
# were run to the screen.

echo ""

cat << EOF
  --> HOSTNAME: ${NODE}
  --> IP: ${IPADDR}
  --> OS: ${OS} ${OSREV}

EOF

# Make sure they really want to run script.
# Ask user to answer 'YES' in all caps, or the script exits.

    ask(){
          agree=""
    while [ "X$agree" = "X" ]; do
        echo "Do you want to run this script? [YES or no] "
        read agree
            case ${agree} in
                YES) echo "OK running script ..." ;;
                n*|N*)  echo "OK quitting ... exit";
                        exit 0;;
                *) echo "" ;
                   echo "Please enter YES [in caps] if you wish to run the hardening scripts.";
                   echo "" ;
                ask ;;
            esac
    done
    }
ask

# Perform backup of all config files touched by hardening
# in case of the need to revert system to pre-hardened state.

# Backup configuration files

    ./do-backup_rhel5_cis-v1.1.1.sh
    
# Begin hardening

    echo ""
    echo "Executing hardening sub-scripts: `date`"
    echo ""

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

# Comment function to skip it (put # at start of line)
# Uncomment function to run it (remove # at start of line)
# Add comments to section for each hardening step declined

##########################################################################
# RHEL5 Benchmark: Section 2                                             #
# Patches, Packages and Initial Lockdown                                 #
##########################################################################
echo "  * harden_02_rhel5_cis-v1.1.1.sh called"
./harden_02_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 3                                             #
# Minimize xinetd Network Services                                       #
##########################################################################
echo "  * harden_03_rhel5_cis-v1.1.1.sh called"
./harden_03_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 4                                             #
# Minimize Boot Services                                                 #
##########################################################################
echo "  * harden_04_rhel5_cis-v1.1.1.sh called"
./harden_04_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 5                                             #
# System Network Parameter Tuning                                        #
##########################################################################
echo "  * harden_05_rhel5_cis-v1.1.1.sh called"
./harden_05_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 6                                             #
# Logging                                                                #
##########################################################################
echo "  * harden_06_rhel5_cis-v1.1.1.sh called"
./harden_06_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 7                                             #
# File And Directory Permissions/Access                                  #
##########################################################################
echo "  * harden_07_rhel5_cis-v1.1.1.sh called"
./harden_07_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 8                                             #
# System Access, Authentication, and Authorization                       #
##########################################################################
echo "  * harden_08_rhel5_cis-v1.1.1.sh called"
./harden_08_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 9                                             #
# User Accounts and Environment                                          #
##########################################################################
echo "  * harden_09_rhel5_cis-v1.1.1.sh called"
./harden_09_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 10                                            #
# Warning Banners                                                        #
##########################################################################
echo "  * harden_10_rhel5_cis-v1.1.1.sh called"
./harden_10_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 11                                            #
# Misc Odds And Ends                                                     #
##########################################################################
echo "  * harden_11_rhel5_cis-v1.1.1.sh called"
./harden_11_rhel5_cis-v1.1.1.sh

##########################################################################
# RHEL5 Benchmark: Section 13                                            #
# Optional Security Notes                                                #
#                                                                        #
# Custom Hardening Scripts Additional to the RHEL CIS Benchmark          #
# If you have any other hardening related processess that you would like #
# to add, HP Consulting has provided you with a blank script template    #
# for you to customize to suit and this place-holder to launch from.     #
##########################################################################
# echo "  * harden_13_rhel5_cis-v1.1.1.sh called"
# ./harden_13_rhel5_cis-v1.1.1.sh

#---------- END  CONFIGURATION ----------#

echo ""
echo "Hardening complete: `date`"
echo ""
echo "Execute ./do-assess_rhel5_cis-v1.1.1.sh to run CIS-CAT"
echo "assessment tool and verify hardening."
echo ""

# END
