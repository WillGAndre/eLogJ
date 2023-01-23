#!/bin/bash

# TODO: add opt
#  - purge
#  - remote log config

if [ ! -f /etc/rsyslog.d/0-filefwd.conf ]; then
    printf "\t[!] attempting to set default rsyslog local log file config \n"
    sudo touch /etc/rsyslog.d/0-filefwd.conf
    sudo touch /tmp/elogj-info.log
    sudo chmod 766 /tmp/elogj-info.log
    sudo echo 'if ($syslogseverity == 6) then
    {
        action(type="omfile" file="/tmp/elogj-info.log")
    }' >> /etc/rsyslog.d/0-filefwd.conf
    sudo systemctl restart rsyslog

    # log id and priority
    logger -i -p local6.info info-sample-test
    tail /tmp/elogj-info.log | grep info-sample-test
    if [ $? -eq 0 ]; then
        printf "\t[+] info sample test log verified \n"
    else
        printf "\t[-] failed info sample test log \n"
        exit 1
    fi
fi