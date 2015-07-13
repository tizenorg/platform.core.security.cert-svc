#!/bin/bash
source /etc/tizen-platform.conf

ROOT_CERT_SQL=${TZ_SYS_SHARE}/cert-svc/root-cert.sql
CERT_LIST_CRT=${TZ_SYS_SHARE}/cert-svc/ca-certificate.crt

MOZILLA_SSL_DIRECTORY=${TZ_SYS_SHARE}/ca-certificates/mozilla
TIZEN_SSL_DIRECTORY=${TZ_SYS_SHARE}/ca-certificates/tizen

function initialize_store_in_dir {
	for i in `find $1/* -name '*'`
	do
		cert=`openssl x509 -in $i`
		echo $cert >> ${CERT_LIST_CRT}
		echo >> ${CERT_LIST_CRT}

		gname=`echo $i | cut -f 6 -d '/'`
		filehash=`openssl x509 -in $i -hash -noout`
		subjecthash=`openssl x509 -in $i -subject_hash_old -noout`

		commonname=`openssl x509 -in $i -subject -noout -nameopt multiline | grep commonName | cut -f 2 -d =`
		if [[ $commonname == "" ]]; then
			commonname=`openssl x509 -in $i -subject -noout -nameopt multiline | grep organizationUnitName | cut -f 2 -d =`
		fi
		if [[ $commonname == "" ]]; then
			commonname=`openssl x509 -in $i -subject -noout -nameopt multiline | grep organizationName | cut -f 2 -d =`
		fi
		if [[ $commonname == "" ]]; then
			commonname=`openssl x509 -in $i -subject -noout -nameopt multiline | grep emailAddress | cut -f 2 -d =`
		fi

		commonname=${commonname:1} # cut first whitespace

		echo "INSERT INTO ssl (gname, certificate, file_hash, subject_hash, common_name, enabled, is_root_app_enabled) values (\"$gname\", \"$cert\", \"$filehash\", \"$subjecthash\", \"$commonname\", 1, 1);" >> ${ROOT_CERT_SQL}
	done
}

if [[ -e $ROOT_CERT_SQL ]]
then
	rm $ROOT_CERT_SQL
fi

if [[ -e $CERT_LIST_CRT ]]
then
	rm $CERT_LIST_CRT
fi

touch $ROOT_CERT_SQL
touch $CERT_LIST_CRT

initialize_store_in_dir $MOZILLA_SSL_DIRECTORY
initialize_store_in_dir $TIZEN_SSL_DIRECTORY

chown system:system ${CERT_LIST_CRT}
chmod 644 ${CERT_LIST_CRT}

echo "initialize_store_db.sh done"
