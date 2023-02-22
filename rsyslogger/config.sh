#!/bin/bash
log_type=$1
readonly WM_ADDR="192.168.1.54"

if [ "$log_type" = "file" ] || [ "$log_type" = "local" ]; then
    if [ ! -f /etc/rsyslog.d/0-filefwd.conf ]; then
        printf "\t[!] attempting to set rsyslog local log file config \n"
        sudo touch /etc/rsyslog.d/0-filefwd.conf
        sudo touch /tmp/elogj-info.log
        sudo chmod 766 /tmp/elogj-info.log
        echo 'if ($syslogseverity == 6) then
        {
            action(type="omfile" file="/tmp/elogj-info.log")
        }' | sudo tee -a /etc/rsyslog.d/0-filefwd.conf
        sudo systemctl restart rsyslog

        # log id and priority
        logger -i -t elogj.info -p local6.info info-sample-test
        tail /tmp/elogj-info.log | grep info-sample-test
        if [ $? -eq 0 ]; then
            printf "\t[+] info sample test log verified \n"
        else
            printf "\t[-] failed info sample test log \n"
            exit 1
        fi
    fi
elif [ $log_type = "manager" ]; then
    if [ ! -f /etc/rsyslog.d/0-filefwd.conf ]; then
        printf "\t[!] attempting to set rsyslog Wazuh Manager forward logger config \n"
        sudo touch /etc/rsyslog.d/0-filefwd.conf
        sudo touch /tmp/elogj-info.log
        sudo chmod 766 /tmp/elogj-info.log
        echo "if (\$syslogseverity == 6) then
{
    *.* action(type=\"omfwd\"
        queue.type=\"linkedlist\"
        action.resumeRetryCount=\"-1\"
        target=\"$WM_ADDR\" port=\"514\" protocol=\"udp\"
    )
}" | sudo tee -a /etc/rsyslog.d/0-filefwd.conf
        sudo systemctl restart rsyslog
        logger -i -t elogj.info -p local6.info {"app":"core","message":"Login failed: 'admin' (Remote IP: '127.0.0.1', X-Forwarded-For: '')","level":2,"time":"2015-06-09T08:16:29+00:00","@source":"ownCloud"}
    fi
fi