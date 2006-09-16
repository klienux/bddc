#!/bin/bash
# bddc version 0.0.7
#####################################################################################
# licensed under the                                                                #
# The MIT License                                                                   #
#                                                                                   #
# Copyright (c) <2006> <florian[at]klien[dot]cx>                                    #
#                                                                                   #
# Permission is hereby granted, free of charge, to any person obtaining a copy of   #
# this software and associated documentation files (the "Software"), to deal in the #
# Software without restriction, including without limitation the rights to use,     #
# copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the   #
# Software, and to permit persons to whom the Software is furnished to do so,       #
# subject to the following conditions:                                              #
#                                                                                   #
#                                                                                   #
# The above copyright notice and this permission notice shall be included in all    #
# copies or substantial portions of the Software.                                   #
#                                                                                   #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR        #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS  #
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR    #
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN #
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION   #
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                   #
#                                                                                   #
# ################################################################################# #
#                                                                                   #
# BashDynDnsChecker (bddc)                                                          #
#                                                                                   #
# This is a dyndns check and synchronizing script                                   #
# the executables it needs are:                                                     #
# grep, egrep, curl, echo, sed, ifconfig, date, tail, cut, cat and rm               #
# which should be available in every linux system.                                  #
#                                                                                   #
# copyright 2006 by florian klien                                                   #
# florian[at]klien[dot]cx                                                           #
#                                                                                   #
# supports ip reception from ifconfig, an external url (by http)                    #
# and parsing from a router.                                                        #
#                                                                                   #
# supports dyndns synchronization with afraid.org, dyndns.org and no-ip.com         #
#                                                                                   #
# it needs to be called in crontab as a cronjob, or any other similar               #
# perpetual program.                                                                #
#                                                                                   #
#                                                                                   #
#                                                                                   #
# if you want your router to be supported,                                          #
# add the following information to the feature request site on sourceforge.net:     #
#                                                                                   #
# *) the url under which the external ip can be read from your router               #
# *) a copy of the html source code from this site (each online and offline)        #
# *) the complete name of your router                                               #
# *) the url to call for logout of the router                                       #
# *) your name and email address for contact and testing purpose before             #
#    a release is done.                                                             #
# OR, what we prefer                                                                #
# *) write your own parsing string, as we do in the script and put it on the        #
#    feature request forum on sourceforge.net.                                      #
# *) plus full name of the router                                                   #
#                                                                                   #
# exit codes:                                                                       #
# 0  -> everything went fine                                                        #
# 1  -> some error occured during runtime                                           #
# 2  -> some config error was caught                                                #
# 28 -> timeout at connecting to some host                                          #
#                                                                                   #
#####################################################################################
# change to your needs                                                              #
#####################################################################################

# executable paths
sed=sed
grep=grep
egrep=egrep
cat=cat
cut=cut
ifconfig=ifconfig
date=date
tail=tail
echo=echo
curl=curl

######################
# change logging level
# 3 -> log whenever a check is done
# 2 -> log when ip changes
# 1 -> log errors
# 0 -> log nothing
LOGGING=2
LOGFILE=/var/log/bddc.log

# cache file for ip address
ip_cache=/tmp/bddc-ip-add.cache

html_tmp_file=/tmp/bddc_html_tmp_file

# turn silent mode on (no echo while running, [1 is silent])
SILENT=1

#################################
# mode of ip checking
# 1 -> output of ifconfig
# 2 -> remote website
# 3 -> router info over http
CHECKMODE=2

#################################
# ad 1: your internet interface
inet_if=eth0

#################################
# ad 2: remote url to get ip from over http
check_url=http://whatismyip.com
# seconds to try for remote host:
remote_timeout=10

########### R O U T E R #########
# ad 3: router model
# 1 -> DLink DI-624
# 2 -> Netgear-TA612V
# 3 -> Netgear WGT-624
ROUTER=1
router_timeout=5
router_tmp_file=/tmp/bddc_router_tmp_file

#-------DLink-DI-624---------
# ad 1: DLink DI-624 conf
dlink_user='ADMIN'
dlink_passwd='PASSWD'
dlink_ip=192.168.0.1
# this helps parsing (do not change)
dlink_url=st_devic.html
dlink_mode=WAN
dlink_wan_mode=PPTP
#------/Dlink-DI-624---------

#-------Netgear-TA612V--------
# ad 2: Netgear-TA612V conf
netgear1_user='ADMIN'
netgear1_passwd='PASSWD'
netgear1_ip=192.168.0.1
# this helps parsing (do not change)
netgear1_url=s_status.htm
netgear1_logout=logout.htm
#------/Netgear-TA612V--------

#-------Netgear WGT-624--------
# ad 3: WGT 624 conf
wgt624_user='ADMIN'
wgt624_passwd='PASSWD'
wgt624_ip=192.168.0.1
# this helps parsing (do not change)
wgt624_url=RST_status.htm
wgt624_logout=LGO_logout.htm
#-------/Netgear WGT-624-------
######### / R O U T E R #########



#####################
# mode of syndication
# 1 -> use afraid.org url
# 2 -> use dyndns.org
# 3 -> use no-ip.com
# T -> testing option (doing nothing)
IPSYNMODE=T


#------------afraid.org-----------------
# ad 1: your update url using afraid.org
# enter your syndication url from afraid.org
afraid_url=http://freedns.afraid.org/dynamic/update.php...........................
#-----------/afraid.org-----------------


#------------dyndns.org----------------
# ad 2: data you got at dyndns.org
dyndnsorg_username='USER'
dyndnsorg_passwd='PASSWD'
dyndnsorg_hostnameS=URL.HOSTNAME-YOU.GOT
#--do not edit-----
dyndnsorg_wildcard=NOCHG
dyndnsorg_mail=NOCHG
dyndnsorg_backmx=NOCHG
dyndnsorg_offline=NO
#for testing
dyndnsorg_ip=
#-----------/dyndns.org----------------

#------------no-ip.com-----------------
# ad 3: your data you got at no-ip.com
# username is an email address
noipcom_username='USERNAME@yourdomain.com'
noipcom_passwd='PASSWD'
noipcom_hostnameS=yoururl.you-got-at-no-ip.org
#for testing
noipcom_ip=
#-----------/no-ip.com-----------------

# the name of the client that is sent with updates and requests
bddc_name="bashdyndnschecker (bddc v0.0.7)/bddc.sf.net"

# the url that needs the dyndns (has no sense in this release)
my_url=your.domain.com

################################################################################
# End of editspace, just go further if you know what you are doing             #
################################################################################

login_data_valid () {
    if [ "$1" == "ADMIN" ] || [ "$2" == "PASSWD" ]; then
        if [ $SILENT -eq 0 ]; then
            $echo "ERROR: check the login settings for your router"
        fi
        if [ $LOGGING -ge 1 ]; then
            $echo "[`$date +%d/%b/%Y:%T`] | ERROR: check the login settings for your router" >> $LOGFILE 
        fi
        return 0;
        fi
    return 1;
}

if [ ! -e ${ip_cache} ] || [ ! -s ${ip_cache} ]; then
    $echo '0.0.0.0' >> ${ip_cache}
fi
if [ $LOGGING -ge 1 ]; then
    if [ ! -e ${LOGFILE} ] || [ ! -s ${LOGFILE} ]; then
        $echo 'BashDynDnsChecker Logfile:' >> ${LOGFILE}
    fi
    if [ ! -r ${LOGFILE} ] || [ ! -w ${LOGFILE} ]; then
        $echo "ERROR: Script has no write and/or no read permission for logfile ${LOGFILE}!"
        exit 2
    fi
fi
if [ ! -r ${ip_cache} ] || [ ! -w ${ip_cache} ]; then
    $echo "ERROR: Script has no write and/or no read permission for ${ip_cache}!"
    $echo "NOTICE: the script needs permission to write to this file too: ${router_tmp_file}"
    if [ $LOGGING -ge 1 ]; then
        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: Script has no write and/or no read permission for ${ip_cache}!" >> $LOGFILE 
    fi
    exit 2
fi

case "$CHECKMODE" in
	# ifconfig mode
    1)
        feedback=`$ifconfig | $grep $inet_if`
        if [ -z '$feedback' ]; then
            if [ $SILENT -eq 0 ]; then
                $echo "ERROR: internet interface is down!"
            fi
            if [ $LOGGING -ge 1 ]; then
                $echo "[`$date +%d/%b/%Y:%T`] | ERROR: internet interface ($inet_if) is down!" >> $LOGFILE && exit 1 
            fi
        fi
        current_ip=`$ifconfig ${inet_if} | grep 'inet ' | $sed 's/[^0-9]*//;s/ .*//'`;
        ;;
    # remote website mode 
    2)
    	# only edit if you know what you do!
    	# edit line of current_ip to a form that only the ip remains when you get the html file
		# in this format: '123.123.132.132'
        string=`$curl --connect-timeout ${remote_timeout} -s -A '${bddc_name}' $check_url -o ${html_tmp_file}`
		if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${remote_timeout} second(s) tried on host: ${check_url})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${remote_timeout} second(s) tried on host: ${check_url})" >> $LOGFILE
            fi
 			exit 28;
		fi
        current_ip=`$cat $html_tmp_file | $egrep -e ^[\ \t]*\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}| $sed 's/ //g'`
		rm $html_tmp_file
        ;;
    
	# router per http mode
    3)   
        case $ROUTER in
        # DLink DI-624
            1)
             	login_data_valid ${dlink_user} ${dlink_passwd}
             	loginIsValid=$?
                if [ $loginIsValid == 0 ]; then
                    exit 2
               	fi
                string=`$curl --connect-timeout '${router_timeout}' -s --anyauth -u ${dlink_user}:"${dlink_passwd}" -o "${router_tmp_file}" http://${dlink_ip}/${dlink_url}`
                if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${router_timeout} second(s) tried on host: http://${dlink_ip}/${dlink_url})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${router_timeout} second(s) tried on host: http://${dlink_ip}/${dlink_url})" >> $LOGFILE
            fi
 			exit 28;
		fi
                line=`$grep -A 20 ${dlink_mode} ${router_tmp_file} | $grep onnected`
                line2=${line#"                    ${dlink_wan_mode} "}
                disconnected=${line2:0:9} # cutting Connected out of file
                if [ "$disconnected" != "Connected" ]; then
                    if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: DLink DI-624 internet interface is down!"
                    fi
                    if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: DLink DI-624 Internet interface is down!" >> $LOGFILE && exit 1
                    fi 
                fi
                current_ip=`$grep -A 30 ${dlink_mode} ${router_tmp_file} | $grep -A 9 ${dlink_wan_mode} | $tail -n 1 | $cut -d " " -f 21`
                rm ${router_tmp_file}
                ;;
            
             # Netgear-TA612V
            2)
             	login_data_valid ${netgear1_user} ${netgear1_passwd}
             	loginIsValid=$?
                if [ $loginIsValid == 0 ]; then
                    exit 2
               	fi
               	string=`$curl --connect-timeout '${router_timeout}' -s --anyauth -u ${netgear1_user}:"${netgear1_passwd}" -o "${router_tmp_file}" http://${netgear1_ip}/${netgear1_url}`
                if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${router_timeout} second(s) tried on host: http://${netgear1_ip}/${netgear1_url})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${router_timeout} second(s) tried on host: http://${netgear1_ip}/${netgear1_url})" >> $LOGFILE 
            fi
 			exit 28;
		fi
               	current_ip=`grep -A 20 'Internet Port' ${router_tmp_file} | grep -A 1 'IP Address'|egrep -e \([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\} | sed 's/<[^>]*>//g;/</N;'|sed 's/^[^0-9]*//;s/[^0-9]*$//'`
                if [ -z "$current_ip" ]; then
                    if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: Netgear-TA612V internet interface is down!"
                    fi
                    if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: Netgear-TA612V Internet interface is down!" >> $LOGFILE && exit 1
                    fi 
                fi
                $curl --connect-timeout '${router_timeout}' -s --anyauth -u ${netgear1_user}:${netgear1_passwd} http://${netgear1_ip}/${netgear1_logout}
                 if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${router_timeout} second(s) tried on host: http://${netgear1_ip}/${netgear1_logout})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${router_timeout} second(s) tried on host: http://${netgear1_ip}/${netgear1_logout})" >> $LOGFILE 
            fi
 			exit 28;
		fi
                rm ${router_tmp_file}
                ;;
            
             # Netgear WGT 624
            3)
             	login_data_valid ${wgt624_user} ${wgt624_passwd}
             	loginIsValid=$?
                if [ $loginIsValid == 0 ]; then
                    exit 2
                fi
                string=`$curl --connect-timeout '${router_timeout}' -s --anyauth -u ${wgt624_user}:"${wgt624_passwd}" -o "${router_tmp_file}" http://${wgt624_ip}/${wgt624_url}`
               if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${router_timeout} second(s) tried on host: http://${wgt624_ip}/${wgt624_url})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${router_timeout} second(s) tried on host: http://${wgt624_ip}/${wgt624_url})" >> $LOGFILE 
            fi
 			exit 28;
		fi
		current_ip=`$grep -A 20 'Internet Port' ${router_tmp_file}| $grep -A 1 'IP Address' | $egrep -e \([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\} | $sed 's/<[^>]*>//g;/</N;'| $sed 's/^[^0-9]*//;s/[^0-9]*$//'`
                if [ "$current_ip" == "0.0.0.0" ]; then
                    if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: WGT 624 internet interface is down!"
                    fi
                    if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: WGT 624 Internet interface is down!" >> $LOGFILE && exit 1
                    fi 
                fi
                $curl --connect-timeout '${router_timeout}' -s --anyauth -u ${wgt624_user}:${wgt624_passwd} http://${wgt624_ip}/${wgt624_logout}
                 if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${router_timeout} second(s) tried on host: http://${wgt624_ip}/${wgt624_logout})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${router_timeout} second(s) tried on host: http://${wgt624_ip}/${wgt624_logout})" >> $LOGFILE 
            fi
 			exit 28;
		fi
                rm ${router_tmp_file}
                ;;
        esac
        
        ;;
esac


#---------IP-syndication-part--------------------


old_ip=`$cat $ip_cache`
if [ "$current_ip" != "$old_ip" ]
    then
    
    $echo $current_ip > $ip_cache
    
    case $IPSYNMODE in
        # afraid.org
        1)
        	# afraid.org gets IP over the http request of your url
            afraid_feedback=`$curl --connect-timeout '${remote_timeout}' -A '${bddc_name}' -s $afraid_url`
             if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${remote_timeout} second(s) tried on host: ${afraid_url})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${remote_timeout} second(s) tried on host: ${afraid_url})" >> $LOGFILE 
            fi
 			exit 28;
			fi
			checker=$afraid_feedback
            if [ "ERROR" = ${checker:0:5} ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "afraid.org: ${afraid_feedback}"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | afraid.org: ${afraid_feedback}" >> $LOGFILE && $echo 0.0.0.0 > $ip_cache && exit 1
                fi 
            fi
            ;;
        
    # dyndns.org
        2)
	    dyndnsorg_ip=$current_ip;
            myurl=`$echo "http://${dyndnsorg_username}:${dyndnsorg_passwd}@members.dyndns.org/nic/update?system=dyndns&hostname=${dyndnsorg_hostnameS}&myip=${dyndnsorg_ip}&wildcard=${dyndnsorg_wildcard}&mx=${dyndnsorg_mail}&backmx=${dyndnsorg_backmx}&offline=${dyndnsorg_offline}"`
            dyndnsorg_feedback=`$curl --connect-timeout '${remote_timeout}' -s -A '${bddc_name}' ${myurl}`
            if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${remote_timeout} second(s) tried on host: ${myurl})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${remote_timeout} second(s) tried on host: ${myurl})" >> $LOGFILE 
            fi
 			exit 28;
			fi
			if [ "${dyndnsorg_feedback:0:8}" == "badagent" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: ERROR The user agent that was sent has been blocked for not following the specifications (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: ERROR The user agent that was sent has been blocked for not following the specifications (${dyndnsorg_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [  "${dyndnsorg_feedback:0:5}" == "abuse" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: ERROR account blocked because of abuse (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: ERROR account blocked because of abuse (${dyndnsorg_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [ "${dyndnsorg_feedback:0:7}" == "notfqdn" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: ERROR domain name is not fully qualified (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: ERROR domain name is not fully qualified (${dyndnsorg_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [ "${dyndnsorg_feedback:0:7}" == "badauth" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: ERROR bad authentication (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: ERROR bad authentication (${dyndnsorg_feedback})" >> $LOGFILE && exit 2
                fi 
            fi
	    if [ "${dyndnsorg_feedback:0:4}" == "good" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: update successful (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "2" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: update successful (${dyndnsorg_feedback})" >> $LOGFILE
                fi
            fi
	    if [ "${dyndnsorg_feedback:0:5}" == "nochg" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "dyndns.org: still the same ip (${dyndnsorg_feedback})"
                fi
                if [ $LOGGING -ge "3" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | dyndns.org: still the same ip (${dyndnsorg_feedback})" >> $LOGFILE
                fi
            fi
	    if [ $SILENT -eq "0" ]; then
                $echo "dyndns.org: $dyndnsorg_feedback"
            fi
   	    ;;
        3)
	    noipcom_ip=$current_ip;
            myurl=`$echo "http://dynupdate.no-ip.com/nic/update?hostname=${noipcom_hostnameS}&myip=${noipcom_ip}"`
            noipcom_feedback=`$curl --connect-timeout '${remote_timeout}' -s -A '${bddc_name}' --basic -u ${noipcom_username}:${noipcom_passwd} ${myurl}`
            if [ "28" -eq `echo $?` ]; then
			if [ $SILENT -eq 0 ]; then
                        $echo "ERROR: timeout (${remote_timeout} second(s) tried on host: ${myurl})"
            fi
            if [ $LOGGING -ge 1 ]; then
                        $echo "[`$date +%d/%b/%Y:%T`] | ERROR: timeout (${remote_timeout} second(s) tried on host: ${myurl})" >> $LOGFILE 
            fi
 			exit 28;
			fi
            if [ "${noipcom_feedback:0:8}" == "badagent" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: ERROR The user agent that was sent has been blocked for not following the specifications (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: ERROR Client disabled. Client should exit and not perform any more updates without user intervention. (${noipcom_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [  "${noipcom_feedback:0:5}" == "abuse" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: ERROR Account disabled due to violation of No-IP terms of service. Our terms of service can be viewed at http://www.no-ip.com/legal/tos (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: ERROR Account disabled due to violation of No-IP terms of service. Our terms of service can be viewed at http://www.no-ip.com/legal/tos (${noipcom_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [ "${noipcom_feedback:0:6}" == "nohost" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: ERROR Hostname supplied does not exist (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: ERROR Hostname supplied does not exist (${noipcom_feedback})" >> $LOGFILE && exit 1
                fi 
            fi
	    if [ "${noipcom_feedback:0:7}" == "badauth" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: ERROR Invalid username (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "1" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: ERROR Invalid username (${noipcom_feedback})" >> $LOGFILE && exit 2
                fi 
            fi
	    if [ "${noipcom_feedback:0:4}" == "good" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: DNS hostname update successful (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "2" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: DNS hostname update successful (${noipcom_feedback})" >> $LOGFILE
                fi
            fi
	    if [ "${noipcom_feedback:0:5}" == "nochg" ]; then
                if [ $SILENT -eq "0" ]; then
                    $echo "no-ip.com: IP address is current, no update performed (${noipcom_feedback})"
                fi
                if [ $LOGGING -ge "3" ]; then
                    $echo "[`$date +%d/%b/%Y:%T`] | no-ip.com: IP address is current, no update performed (${noipcom_feedback})" >> $LOGFILE
                fi
            fi
	    if [ $SILENT -eq "0" ]; then
                $echo "no-ip.com: $noipcom_feedback"
            fi
   	    ;;
        T)
            # testing option for scripting, that you dont get banned from a service
            if [ $SILENT -eq "0" ]; then
                $echo "Performing no update ;)"
            fi
            ;;
    esac
    
    #logging
    if [ $LOGGING -ge "2" ]
        then
        $echo "[`$date +%d/%b/%Y:%T`] | ip changed: $current_ip" >> $LOGFILE
    fi 
    if [ $SILENT -eq "0" ]
        then
        $echo "[`$date +%d/%b/%Y:%T`] | ip changed: $current_ip"
    fi
    #/logging
fi

if [ $LOGGING -ge "3" ]
    then
    $echo "[`$date +%d/%b/%Y:%T`] | current ip: $current_ip" >> $LOGFILE
fi
if [ $SILENT -eq "0" ]
    then
    $echo "[`$date +%d/%b/%Y:%T`] | current ip: $current_ip"
fi
exit 0 
