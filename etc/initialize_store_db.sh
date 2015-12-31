#!/bin/bash

DB_PATH=$1
SYSTEM_SSL_DIR=$2

ROOT_CERT_SQL=root-cert.sql

function get_field()
{
	local fname=$1
	local field=$2

	echo "`openssl x509 -in $fname -subject -noout -nameopt multiline \
			| grep $field \
			| cut -f 2 -d =`"
}

function get_common_name()
{
	local fname=$1
	local common_name=

	common_name=`get_field $fname commonName`
	if [[ $common_name == "" ]]; then
		common_name=`get_field $fname organizationUnitName`
	fi
	if [[ $common_name == "" ]]; then
		common_name=`get_field $fname organizationName`
	fi
	if [[ $common_name == "" ]]; then
		common_name=`get_field $fname emailAddress`
	fi

	echo "${common_name:1}" # cut first whitespace
}

function initialize_store()
{
	for fname in `find $SYSTEM_SSL_DIR/*`
	do
		gname=`echo ${fname##*/}`
		if [[ ! $gname =~ ^[0-9a-z]{8}\.[0-9]$ ]]; then
			continue
		fi

		cert=`openssl x509 -in $fname -outform PEM`
		subject_hash=`openssl x509 -in $fname -subject_hash -noout`
		subject_hash_old=`openssl x509 -in $fname -subject_hash_old -noout`
		common_name=`get_common_name $fname`

		echo "INSERT INTO ssl \
				(gname, certificate, file_hash, subject_hash, \
				common_name, enabled, is_root_app_enabled) values \
				(\"$gname\", \"$cert\", \"$subject_hash\", \"$subject_hash_old\", \
				\"$common_name\", 1, 1);" >> $ROOT_CERT_SQL
	done
}

touch $ROOT_CERT_SQL

initialize_store

cat $ROOT_CERT_SQL | sqlite3 $DB_PATH

rm $ROOT_CERT_SQL
