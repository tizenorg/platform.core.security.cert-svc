#!/bin/bash
source /etc/tizen-platform.conf

MOZILLA_SSL_DIRECTORY=${TZ_SYS_SHARE}/ca-certificates/mozilla
TIZEN_SSL_DIRECTORY=${TZ_SYS_SHARE}/ca-certificates/tizen

CRT_PATH=${TZ_SYS_SHARE}/cert-svc/ca-certificate.crt

function append_to_crt_file {
	for i in `find $1/* -name '*'`
	do
		openssl x509 -in $i -outform PEM >> $CRT_PATH
	done
}

if [ -e $CRT_PATH ]
then
    rm $CRT_PATH
fi

touch $CRT_PATH

append_to_crt_file $MOZILLA_SSL_DIRECTORY
append_to_crt_file $TIZEN_SSL_DIRECTORY

chown system:system ${CRT_PATH}
chmod 644 ${CRT_PATH}

echo "make-ca-certificate.sh done"
