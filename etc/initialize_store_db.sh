#!/bin/bash
source /etc/tizen-platform.conf

DB_PATH=$1
CRT_PATH=$2

ROOT_CERT_SQL=root-cert.sql
SYSTEM_SSL_DIR=$TZ_SYS_ETC/ssl/certs

function initialize_store {
	for i in `find $SYSTEM_SSL_DIR/* -name '*'`
	do
		gname=`echo $i | cut -f 5 -d '/'`
		if [[ ! $gname =~ ^[0-9a-z]{8}\.[0-9]$ ]]; then
			continue
		fi

		cert=`openssl x509 -in $i -outform PEM`
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

		echo "INSERT INTO ssl (gname, certificate, file_hash, subject_hash, common_name, enabled, is_root_app_enabled) values (\"$gname\", \"$cert\", \"$filehash\", \"$subjecthash\", \"$commonname\", 1, 1);" >> $ROOT_CERT_SQL

		openssl x509 -in $i -outform PEM >> $CRT_PATH
	done
}

touch $ROOT_CERT_SQL
touch $CRT_PATH

initialize_store

cat $ROOT_CERT_SQL | sqlite3 $DB_PATH
rm $ROOT_CERT_SQL
