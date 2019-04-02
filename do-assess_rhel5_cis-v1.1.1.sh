#!/bin/sh

#
# do-assess_rhel5_cis-v1.1.1.sh
##########################################################################
# AUTHOR: Jack Maynard                                                   #
# Created: May 10, 2010 - version 1.0                                    #
#                                                                        #
# RedHat Enterprise Linux 5 (RHEL5)  Security Hardening ASSESS Script    #
# This script launches the CIS Configuration Audit Tool (CIS-CAT)        #
# Scripted to Center for Internet Security (CIS) RHEL5 Benchmark v1.1.1  #
# www.cisecurity.org                                                     #
##########################################################################

# Variable Declarations

    TIMESTAMP="`date '+%Y%m%d_%H%M%S'`"
    REPORT_DIR=/opt/hp/security/harden/reports/cis-cat/${TIMESTAMP}

##########################################################################
#   Run the CIS Configuration Audit Tool                                 #
##########################################################################
run_cis_cat(){

# Create the report directory if it does not exist

    mkdir -p ${REPORT_DIR}
    chown root:root ${REPORT_DIR}
    chmod 700 ${REPORT_DIR}

    clear
    echo ""
    echo "Running CIS-CAT ..."
    echo ""

# Run RIM Profile:

    cd /opt/hp/security/harden/tools/cis-cat

    ./CIS-CAT.sh ./benchmarks/RIM_RHEL5_Benchmark_v1.1.2-05.xml

    rm    ${HOME}/CIS-CAT_Results/*.xml 
    mv    ${HOME}/CIS-CAT_Results/*.txt ${REPORT_DIR}
    mv    ${HOME}/CIS-CAT_Results/*.html ${REPORT_DIR}
    rmdir ${HOME}/CIS-CAT_Results

    echo ""
    echo "Finished running CIS-CAT!"
    echo ""
    echo "Assessment report moved to the following directory:" 
    echo ""
    echo "  -----> ../reports/cis-cat/`basename ${REPORT_DIR}`"
    echo ""
}

#---------- BEGIN CONFIGURATION ----------#

# TO CHANGE SCRIPT BEHAVIOR ONLY EDIT THE SECTIONS BELOW THIS LINE !!!

##########################################################################
#                                                                        #
#       CONFIGURATION                                                    #
#       Assessment Item Launch                                           #
#                                                                        #
##########################################################################

##########################################################################
#   Run the CIS-CAT Benchmark Tool                                       #
##########################################################################

run_cis_cat

# END
