#!/bin/bash
source /etc/tizen-platform.conf

DB_PATH=$1
CRT_PATH=$2

ROOT_CERT_SQL=root-cert.sql
MOZILLA_SSL_DIRECTORY=$TZ_SYS_SHARE/ca-certificates/mozilla
TIZEN_SSL_DIRECTORY=$TZ_SYS_SHARE/ca-certificates/tizen

function initialize_store_in_dir {
	for i in `find $1/* -name '*'`
	do
		openssl x509 -in $i -outform PEM >> $CRT_PATH
#		echo >> $CRT_PATH

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

		echo "INSERT INTO ssl (gname, certificate, file_hash, subject_hash, common_name, enabled, is_root_app_enabled) values (\"$gname\", \"$cert\", \"$filehash\", \"$subjecthash\", \"$commonname\", 1, 1);" >> $ROOT_CERT_SQL
	done
}

touch $ROOT_CERT_SQL
touch $CRT_PATH

initialize_store_in_dir $MOZILLA_SSL_DIRECTORY
initialize_store_in_dir $TIZEN_SSL_DIRECTORY

cat $ROOT_CERT_SQL | sqlite3 $DB_PATH
rm $ROOT_CERT_SQL
