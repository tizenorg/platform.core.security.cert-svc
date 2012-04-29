/*
 * certification service
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <error.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "cert-service.h"

#define DPS_OPERATION_SUCCESS	0
#define DPS_FILE_ERR			-1
#define DPS_MEMORY_ERR			-2
#define DPS_PARAMETER_ERR		-3
#define DPS_INVALID_OPERATION	-4

#define SDK_CERT_PATH		"./SDK.crt"
#define SDK_PRIVKEY_PATH	"./SDK.key"
#define CA_PRIVKEY_PATH		"./ca.key"

void print_usage(void)
{
	fprintf(stdout, "\n This program signs or verifies signature on package(.deb).\n\n");
	fprintf(stdout, " [USAGE] dpkg-pki-sig [COMMAND] [ARGUMENT(s)]\n\n");
	fprintf(stdout, " - COMMAND:\n");
	fprintf(stdout, "   -- gencert [SDK prikey path] [SDK cert path] [CA prikey path] [CA cert path] [output directory] ([target info])\n");
	fprintf(stdout, "             : generates certificate for SDK, and that certificate will be signed by CA.\n");
	fprintf(stdout, "             : If you use target which be linked your SDK, you must use target information in specific storage of target.\n");
	fprintf(stdout, "               Otherwise, your package does not be executed in target.\n");
	fprintf(stdout, "   -- sign [debian package path] [private key path of user] [certificate path of user]\n");
	fprintf(stdout, "             : signs your debian package with inputed secret key.\n");
	fprintf(stdout, "   -- verify [debian package path]\n");
	fprintf(stdout, "             : verifies your debian package with public key in pre-defined certificate.\n\n");
	fprintf(stdout, " - EXAMPLES:\n");
	fprintf(stdout, "   -- dpkg-pki-sig gencert ./SDKpri.key ./SDKcert.crt ./CApri.key ./CAcert.crt ./ (target info)\n");
	fprintf(stdout, "   -- dpkg-pki-sig sign ./test.deb ./private.key ./mycert.crt\n");
	fprintf(stdout, "   -- dpkg-pki-sig verify ./test.deb\n\n");
}

int delete_directory(const char* path)
{
	int ret = DPS_OPERATION_SUCCESS;
	DIR* dir = NULL;
	struct dirent* dirent = NULL;
	char filename[128];

	if((dir = opendir(path)) == NULL) {
		fprintf(stderr, "[ERR][%s] Fail to open directory, [%s]\n", __func__, path);
		ret = DPS_FILE_ERR;
		goto err;
	}

	while((dirent = readdir(dir)) != NULL) {
		memset(filename, 0x00, 128);
		if((strncmp(dirent->d_name, ".", 1) == 0) || (strncmp(dirent->d_name, "..", 2) == 0))
			continue;
		snprintf(filename, 128, "%s/%s", path, dirent->d_name);
		if(unlink(filename) != 0) {
			fprintf(stderr, "[ERR][%s] Fail to remove file, [%s]\n", __func__, filename);
			perror("ERR!!");
			ret = DPS_FILE_ERR;
			goto err;
		}
	}

	if(rmdir(path) != 0) {
		fprintf(stderr, "[ERR][%s] Fail to remove directory, [%s]\n", __func__, path);
		ret = DPS_FILE_ERR;
		goto err;
	}
			
err:
	if(dir != NULL) closedir(dir);

	return ret;
}

int get_files_from_deb(FILE* fp_deb)
{
	int ret = DPS_OPERATION_SUCCESS;
	int readcount = 0;
	int writecount = 0;
	unsigned long int size = 0;
	FILE* fp_control = NULL;
	FILE* fp_data = NULL;
	FILE* fp_sig = NULL;
	char tempbuf[64];
	char filename[16];
	char filelen[10];
	char* buf = NULL;

	memset(tempbuf, 0x00, 64);
	memset(filename, 0x00, 16);
	memset(filelen, 0x00, 10);

	if(!(fp_control = fopen("./temp/control.tar.gz", "wb"))) {
		fprintf(stderr, "[ERR][%s] Fail to open file, [control.tar.gz]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	if(!(fp_data = fopen("./temp/data.tar.gz", "wb"))) {
		fprintf(stderr, "[ERR][%s] Fail to open file, [data.tar.gz]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	if(!(fp_sig = fopen("./temp/_sigandcert", "wb"))) {
		fprintf(stderr, "[ERR][%s] Fail to open file, [_sigandcert]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}

	while(fgets(tempbuf, 64, fp_deb)) {
		strncpy(filename, tempbuf, 16);
		if(memcmp(filename, "!<arch>\n", 8) == 0)
			continue;
		if((memcmp(filename, "control.tar.gz", 14) == 0) ||
				(memcmp(filename, "data.tar.gz", 11) == 0) ||
				(memcmp(filename, "_sigandcert", 11) == 0)
				) {
			strncpy(filelen, tempbuf + 48, 10);
			size = strtoul(filelen, NULL, 10);
			
			if(!(buf = (char*)malloc(sizeof(char) * (int)size))) {
				fprintf(stderr, "[ERR][%s] Fail to allocate memory\n", __func__);
				ret = DPS_MEMORY_ERR;
				goto err;
			}
			memset(buf, 0x00, (int)size);
			
			if((readcount = fread(buf, sizeof(char), (int)size, fp_deb)) != (int)size) {	// read error
				fprintf(stderr, "[ERR][%s] Read error, [%s]\n", __func__, filename);
				ret = DPS_FILE_ERR;
				goto err;
			}

			if(!strncmp(filename, "control.tar.gz", 14))
				writecount = fwrite(buf, sizeof(char), (int)size, fp_control);
			else if(!strncmp(filename, "data.tar.gz", 11))
				writecount = fwrite(buf, sizeof(char), (int)size, fp_data);
			else if(!strncmp(filename, "_sigandcert", 11))
				writecount = fwrite(buf, sizeof(char), (int)size, fp_sig);
			
			if(writecount != (int)size) {	// write error
				fprintf(stderr, "[ERR][%s] Write error, [%s]\n", __func__, filename);
				ret = DPS_FILE_ERR;
				goto err;
			}

			free(buf);
			buf = NULL;
		}
	}
	
err:
	if(fp_control != NULL) fclose(fp_control);
	if(fp_data != NULL) fclose(fp_data);
	if(fp_sig != NULL) fclose(fp_sig);

	if(buf != NULL) free(buf);

	return ret;
}

int sha256_hash(char* in, unsigned char* out, int len)
{
	int ret = DPS_OPERATION_SUCCESS;
	SHA256_CTX sctx;

	if(!SHA256_Init(&sctx)) {
		fprintf(stderr, "[ERR][%s] Fail to init hash structure\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	if(!SHA256_Update(&sctx, in, len)) {
		fprintf(stderr, "[ERR][%s] Fail to update hash structure\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	if(!SHA256_Final(out, &sctx)) {
		fprintf(stderr, "[ERR][%s] Fail to final hash structure\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

err:
	return ret;
}

int sha256_hashing_file(FILE* fp_file, char* out)
{
	int filelen = 0;
	int i = 0;
	char* in = NULL;
	unsigned char* hashout = NULL;
	int ret = DPS_OPERATION_SUCCESS;
	
	fseek(fp_file, 0L, SEEK_END);
	filelen = ftell(fp_file);
	fseek(fp_file, 0L, SEEK_SET);

	if(!(in = (char*)malloc(sizeof(char) * (filelen + 1)))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory.", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	if(!(hashout = (unsigned char*)malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory.", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	memset(in, 0x00, (filelen + 1));
	memset(hashout, 0x00, SHA256_DIGEST_LENGTH);
	
	if(fread(in, sizeof(char), filelen, fp_file) != filelen) {
		fprintf(stderr, "[ERR][%s] Fail to read file.[%d]\n", __func__, filelen);
		ret = DPS_FILE_ERR;
		goto err;
	}

	if((ret = sha256_hash(in, hashout, filelen)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to hash message\n", __func__);
		goto err;
	}

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(out + (i * 2), "%02x", hashout[i]);
	}

err:
	if(in != NULL) free(in);
	if(hashout != NULL) free(hashout);
	
	return ret;
}

int get_target_info(char* info)
{
#define TARGET_INFO	"/opt/share/cert-svc/targetinfo"
	FILE* fp_info = NULL;
	char* token = NULL;
	char seps[] = " \t\n\r";
	char buf[16];
	int ret = DPS_OPERATION_SUCCESS;

	memset(buf, 0x00, 16);

	if(!(fp_info = fopen(TARGET_INFO, "r"))) {	// error
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, TARGET_INFO);
		ret = DPS_FILE_ERR;
		goto err;
	}

	fgets(buf, 16, fp_info);
	if(buf[0] == '0') {	// not used
		// do nothing
		strncpy(info, "NOT USED", 8);
	}
	else if(buf[0] == '1') {
		memset(buf, 0x00, 16);
		fgets(buf, 16, fp_info);
		memcpy(info, buf, 10);
	}
	else {
		fprintf(stderr, "[ERR][%s] Check your targetinfo file.\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

err:
	return ret;
}

int generate_sdk_cert(int argc, const char** argv)
{
	int ret = DPS_OPERATION_SUCCESS;
	const char* targetinfo = NULL;
	char* defaultinfo = "SDK_simulator";
	int pid = -1;

	/* this code is for testing */
	if((argc < 4) || (argc > 5)) {
		fprintf(stderr, "[ERR][%s] Check your argument!!\n", __func__);
		print_usage();
		ret = DPS_PARAMETER_ERR;
		goto err;
	}

	// delete older SDK cert and SDK key
	if(unlink(argv[0]) != 0) {	// error
		if(errno == ENOENT)
			fprintf(stderr, "[LOG][%s] %s is not exist.\n", __func__, argv[0]);
	}
	if(unlink(argv[1]) != 0) {	// error
		if(errno == ENOENT)
			fprintf(stderr, "[LOG][%s] %s is not exist.\n", __func__, argv[1]);
	}
	
	// get target information
	if(argc == 4)	// target info is not set
		targetinfo = defaultinfo;
	else if(argc == 5)	// target info is set
		targetinfo = argv[4];

	/* execute script '/usr/bin/make_cert.sh' */
	pid = fork();
	if(pid == 0) {	// child
		execl("/usr/bin/make_cert.sh", "/usr/bin/make_cert.sh", argv[0], argv[1], argv[2], argv[3], targetinfo, NULL);
	}
	else if(pid > 0) {	// parent
		wait((int*)0);
		ret = DPS_OPERATION_SUCCESS;
		goto err;
	}
	else if(pid < 0) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to fork.\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

err:
	
	return ret;
}

int package_sign(int argc, const char** argv)
{
	int ret = DPS_OPERATION_SUCCESS;
	int ch = 0, i = 0;
	int certwrite = 0;
	unsigned long int privlen = 0;
	unsigned long int encodedlen = 0;
	unsigned long int certlen = 0;
	unsigned long int sigfilelen = 0;
	FILE* fp_deb = NULL;
	FILE* fp_control = NULL;
	FILE* fp_data = NULL;
	FILE* fp_sig = NULL;
	FILE* fp_priv = NULL;
	FILE* fp_cert = NULL;
	char tempbuf[128];
	char* out = NULL;
	char signingmsg[128];
	char* prikey = NULL;
	unsigned char* r_signature = NULL;
	unsigned char* siginput = NULL;
	char* encoded = NULL;
	char* certbuf = NULL;
	char* startcert = NULL;
	char* endcert = NULL;
	char sigfileinfo[60];
	char* sigfilebuf = NULL;
	unsigned int slen;
	
	RSA* private_key = NULL;
	BIO* private_bio = NULL;

	char* messages = "MESSAGES:\n";
	char* signature = "SIGNATURE:\n";
	char* certificate = "CERTIFICATE:\n";

	if(!(out = (char*)malloc(sizeof(char) * (SHA256_DIGEST_LENGTH * 2 + 1)))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}	
	memset(tempbuf, 0x00, 128);
	memset(signingmsg, 0x00, 128);
	memset(sigfileinfo, 0x00, 60);

	if(argc != 3) {	// debian package, private key, certificate
		fprintf(stderr, "[ERR][%s] Check your argument!!\n", __func__);
		print_usage();
		ret = DPS_PARAMETER_ERR;
		goto err;
	}

	/* make temp dir in current dir */
	if(mkdir("./temp", 0755) != 0) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to make temporary directory, [%s]\n", __func__, "./temp");
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

	/* make signature file in temp dir */
	if(!(fp_sig = fopen("./temp/_sigandcert", "w+b"))) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, "./temp/_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	/* extract .tar.gz file from deb file and store in temp dir */
	if(!(fp_deb = fopen(argv[0], "r+b"))) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, argv[0]);
		ret = DPS_FILE_ERR;
		goto err;
	}

	if((ret = get_files_from_deb(fp_deb)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to extract files from deb.\n", __func__);
		goto err;
	}
	
	if(!(fp_control = fopen("./temp/control.tar.gz", "rb"))) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, "./temp/control.tar.gz");
		ret = DPS_FILE_ERR;
		goto err;
	}
	if(!(fp_data = fopen("./temp/data.tar.gz", "rb"))) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, "./temp/data.tar.gz");
		ret = DPS_FILE_ERR;
		goto err;
	}
		
	/* calculate hash value of .tar.gz file and write */
	if(fwrite(messages, sizeof(char), strlen(messages), fp_sig) != strlen(messages)) {	// error
		fprintf(stderr, "[ERR][%s] Fail to write to file, [%s]\n", __func__, "_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}

	memset(out, 0x00, (SHA256_DIGEST_LENGTH * 2 + 1));
	if((ret = sha256_hashing_file(fp_control, out)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to calculate hash, [%s]\n", __func__, "control.tar.gz");
		goto err;
	}
	snprintf(tempbuf, 128, "%s control.tar.gz\n", out);
	strncpy(signingmsg, tempbuf, strlen(tempbuf));
	
	memset(out, 0x00, (SHA256_DIGEST_LENGTH * 2 + 1));
	if((ret = sha256_hashing_file(fp_data, out)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to calculate hash, [%s]\n", __func__, "control.tar.gz");
		goto err;
	}
	snprintf(tempbuf, 128, "%s data.tar.gz\n", out);
	strncat(signingmsg, tempbuf, strlen(tempbuf));

	fprintf(fp_sig, "%d\n", strlen(signingmsg));
	if(fwrite(signingmsg, sizeof(char), strlen(signingmsg), fp_sig) != strlen(signingmsg)) {
		fprintf(stderr, "[ERR][%s] Fail to write to file, [%s]\n", __func__, "_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}

	/* create signature and write */
	if(fwrite(signature, sizeof(char), strlen(signature), fp_sig) != strlen(signature)) {	// error
		fprintf(stderr, "[ERR][%s] Fail to write to file, [%s]\n", __func__, "_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	if(!(fp_priv = fopen(argv[1], "r"))) {	// error
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, argv[1]);
		ret = DPS_FILE_ERR;
		goto err;
	}
	fseek(fp_priv, 0L, SEEK_END);
	privlen = ftell(fp_priv);
	fseek(fp_priv, 0L, SEEK_SET);

	if(!(prikey = (char*)malloc(sizeof(char) * (int)privlen))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	memset(prikey, 0x00, (int)privlen);

	i = 0;
	while((ch = fgetc(fp_priv)) != EOF) {
		prikey[i] = ch;
		i++;
	}
	prikey[i] = '\0';

	if(!(private_bio = BIO_new_mem_buf(prikey, -1))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory, [private_bio]\n", __func__);
		ERR_print_errors_fp(stdout);
		ret = DPS_MEMORY_ERR;
		goto err;
	}

	if(!(private_key = PEM_read_bio_RSAPrivateKey(private_bio, NULL, NULL, NULL))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory, [private_key]\n", __func__);
		ERR_print_errors_fp(stdout);
		ret = DPS_MEMORY_ERR;
		goto err;
	}

	if(!(r_signature = (unsigned char*)malloc(RSA_size(private_key)))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory, [r_signature]\n", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}

	if(!(siginput = (unsigned char*)malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory.", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	memset(siginput, 0x00, SHA256_DIGEST_LENGTH);

	if((ret = sha256_hash(signingmsg, siginput, strlen(signingmsg))) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to hash\n", __func__);
		goto err;
	}
	
	if(RSA_sign(NID_sha256, siginput, SHA256_DIGEST_LENGTH, r_signature, &slen, private_key) != 1) {	// error
		fprintf(stderr, "[ERR][%s] Fail to make signature.\n", __func__);
		ERR_print_errors_fp(stdout);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

	encodedlen = (((slen + 2) / 3) * 4) + 1;
	if(!(encoded = (char*)malloc(sizeof(char) * encodedlen))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory, [encoded]\n", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	if((ret = cert_svc_util_base64_encode(r_signature, slen, encoded, &encodedlen)) != 0) {	// error
		fprintf(stderr, "[ERR][%s] Fail to encode signature\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	
	fprintf(fp_sig, "%d\n", (int)encodedlen);
	if(fwrite(encoded, sizeof(char), (int)encodedlen, fp_sig) != (int)encodedlen) {	// error
		fprintf(stderr, "[ERR][%s] Fail to write to file, [%s]\n", __func__, "_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}
	fwrite("\n", sizeof(char), 1, fp_sig);

	/* certificate write */
	if(fwrite(certificate, sizeof(char), strlen(certificate), fp_sig) != strlen(certificate)) {	// error
		fprintf(stderr, "[ERR][%s] Fail to write to file, [%s]\n", __func__, "_sigandcert");
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	if(!(fp_cert = fopen(argv[2], "r"))) {	// error
		fprintf(stderr, "[ERR][%s] Fail to open file, [%s]\n", __func__, argv[2]);
		ret = DPS_FILE_ERR;
		goto err;
	}
	fseek(fp_cert, 0L, SEEK_END);
	certlen = ftell(fp_cert);
	fseek(fp_cert, 0L, SEEK_SET);

	if(!(certbuf = (char*)malloc(sizeof(char) * (int)certlen))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	memset(certbuf, 0x00, (int)certlen);

	i = 0;
	while((ch = fgetc(fp_cert)) != EOF) {
		if(ch != '\n') {
			certbuf[i] = ch;
			i++;
		}
	}
	certbuf[i] = '\0';

	startcert = strstr(certbuf, "-----BEGIN CERTIFICATE-----") + strlen("-----BEGIN CERTIFICATE-----");
	endcert = strstr(certbuf, "-----END CERTIFICATE-----");
	certwrite = (int)endcert - (int)startcert;

	fprintf(fp_sig, "%d\n", certwrite);
	if(fwrite(startcert, sizeof(char), certwrite, fp_sig) != certwrite) {	// error
		fprintf(stderr, "[ERR][%s] Fail to write to file, [_sigandcert]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}

	/* insert file into deb archive */
	sigfilelen = ftell(fp_sig);
	fseek(fp_sig, 0L, SEEK_SET);
	fseek(fp_deb, 0L, SEEK_END);

	if(!(sigfilebuf = (char*)malloc(sizeof(char) * (sigfilelen + 1)))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory, [sigfilebuf]\n", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	memset(sigfilebuf, 0x00, (sigfilelen + 1));
	
	snprintf(sigfileinfo, 60, "%-16s%-12ld%-6d%-6d%-8s%-10ld`", "_sigandcert", time(NULL), 0, 0, "100644", sigfilelen);
	fprintf(fp_deb, "%s\n", sigfileinfo);

	if(fread(sigfilebuf, sizeof(char), sigfilelen, fp_sig) != sigfilelen) {
		fprintf(stderr, "[ERR][%s] Fail to read file, [fp_sig]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	if(fwrite(sigfilebuf, sizeof(char), sigfilelen, fp_deb) != sigfilelen) {
		fprintf(stderr, "[ERR][%s] Fail to read file, [fp_sig]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	/* delete temp dir */
	if(delete_directory("./temp") != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to delete directory\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

err:
	if(private_bio != NULL) BIO_free(private_bio);
	
	if(out != NULL) free(out);
	if(prikey != NULL) free(prikey);
	if(r_signature != NULL) free(r_signature);
	if(encoded != NULL) free(encoded);
	if(certbuf != NULL) free(certbuf);
	if(sigfilebuf != NULL) free(sigfilebuf);
	if(siginput != NULL) free(siginput);
	
	if(fp_deb != NULL) fclose(fp_deb);
	if(fp_control != NULL) fclose(fp_control);
	if(fp_data != NULL) fclose(fp_data);
	if(fp_sig != NULL) fclose(fp_sig);
	if(fp_priv != NULL) fclose(fp_priv);
	if(fp_cert != NULL) fclose(fp_cert);
	
	return ret;
}

int package_verify(int argc, const char** argv)
{
	int ret = DPS_OPERATION_SUCCESS;
	/* file pointers */
	FILE* fp_deb = NULL;		// .deb
	FILE* fp_sig = NULL;		// _sigandcert
	/* memory buffer for _sigandcert */
	char* msg = NULL;	// message buffer
	int msglen = 0;		// message length
	char* sig = NULL;	// signature buffer
	int siglen = 0;		// signature length
	char* cert = NULL;	// certificate buffer
	int certlen = 0;	// certificate length
	/* temporary buffer */
	char filebuf[64];	// temp buf for deb
	/* used for cert verification */
	char* target_info = NULL;
	CERT_CONTEXT* ctx = NULL;
	int val_cert = 0;
	int val_sig = 0;

	if(argc != 1) {
		fprintf(stderr, "[ERR] Check your argument!!\n");
		print_usage();
		ret = DPS_PARAMETER_ERR;
		goto err;
	}

	ctx = cert_svc_cert_context_init();

	/* make temp dir in current dir */
	if(mkdir("./temp", 0755) != 0) {	// fail
		fprintf(stderr, "[ERR][%s] Fail to make temporary directory, [%s]\n", __func__, "./temp");
		ret = DPS_INVALID_OPERATION;
		goto err;
	}	
	
	/* extract files from .deb */
	if((fp_deb = fopen(argv[0], "rb")) == NULL) {
		fprintf(stderr, "[ERR][%s] Fail to open file. [%s]\n", __func__, argv[0]);
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	if((ret = get_files_from_deb(fp_deb)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to extract files.\n", __func__);
		goto err;
	}
	
	/* get msg, sig, cert from_sigandcert */
	if((fp_sig = fopen("./temp/_sigandcert", "r")) == NULL) {
		fprintf(stderr, "[ERR][%s] Fail to open file. [_sigandcert]\n", __func__);
		ret = DPS_FILE_ERR;
		goto err;
	}
	
	memset(filebuf, 0x00, 64);
	while(fgets(filebuf, 64, fp_sig) != NULL) {
		if(!strncmp(filebuf, "MESSAGES:", 9)) {
			fgets(filebuf, 64, fp_sig);
			msglen = (int)strtoul(filebuf, NULL, 10);
			msg = (char*)malloc(sizeof(char) * (msglen + 1));
			memset(msg, 0x00, (msglen + 1));
			if(fread(msg, sizeof(char), msglen, fp_sig) != msglen) {
				fprintf(stderr, "[ERR][%s] Fail to get contents from file, [messages]\n", __func__); 
				ret = DPS_INVALID_OPERATION;
				goto err;
			}
		}
		else if(!strncmp(filebuf, "SIGNATURE:", 10)) {
			fgets(filebuf, 64, fp_sig);
			siglen = (int)strtoul(filebuf, NULL, 10);
			sig = (char*)malloc(sizeof(char) * (siglen + 1));
			memset(sig, 0x00, (siglen + 1));
			if(fread(sig, sizeof(char), siglen, fp_sig) != siglen) {
				fprintf(stderr, "[ERR][%s] Fail to get contents from file, [signature]\n", __func__); 
				ret = DPS_INVALID_OPERATION;
				goto err;
			}
		}
		else if(!strncmp(filebuf, "CERTIFICATE:", 12)) {
			fgets(filebuf, 64, fp_sig);
			certlen = (int)strtoul(filebuf, NULL, 10);
			cert = (char*)malloc(sizeof(char) * (certlen + 1));
			memset(cert, 0x00, (certlen + 1));
			if(fread(cert, sizeof(char), certlen, fp_sig) != certlen) {
				fprintf(stderr, "[ERR][%s] Fail to get contents from file, [certificate]\n", __func__); 
				ret = DPS_INVALID_OPERATION;
				goto err;
			}
		}
	}

	/* get certificate data */
	if((ret = cert_svc_load_buf_to_context(ctx, cert)) != CERT_SVC_ERR_NO_ERROR) {
		fprintf(stderr, "[ERR][%s] Fail to load certificate into context, [%d]\n", __func__, ret);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	if((ret = cert_svc_extract_certificate_data(ctx)) != CERT_SVC_ERR_NO_ERROR) {
		fprintf(stderr, "[ERR][%s] Fail to extract certificate data, [%d]\n", __func__, ret);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}

	/* get target info */
	if(!(target_info = (char*)malloc(sizeof(char) * 10))) {
		fprintf(stderr, "[ERR][%s] Fail to allocate memory.\n", __func__);
		ret = DPS_MEMORY_ERR;
		goto err;
	}
	if((ret = get_target_info(target_info)) != DPS_OPERATION_SUCCESS) {
		fprintf(stderr, "[ERR][%s] Fail to get target info.\n", __func__);
		goto err;
	}

	/* check this package is installed by SDK? or app store?
	 * check OU field of certificate
	 *    - if SLP_SDK, be installed by SDK
	 *    - if some other, be installed by app store
	 */
	if(!strncmp(ctx->certDesc->info.subject.organizationUnitName, "SLP SDK", 7)) { // this is SDK
		if(strncmp(target_info, "NOT USED", 8)){ // and use target info(one-to-one matching with target and SDK)
			if(strncmp(ctx->certDesc->info.subject.commonName, target_info, 8)) { // but target_info is not same, error
				fprintf(stderr, "[ERR][%s] target MUST be uniquely matched to SDK.\n", __func__);
				ret = DPS_INVALID_OPERATION;
				goto err;
			}
		}
	}
	
	/* verify certificate */
	if((ret = cert_svc_verify_certificate(ctx, &val_cert)) != CERT_SVC_ERR_NO_ERROR) {
		fprintf(stderr, "[ERR][%s] Fail to verify certificate, [%d]\n", __func__, ret);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	if(val_cert != 1) {	// fail
		fprintf(stdout, "[LOG][%s] certificate is not valid.\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	else {	// success
		fprintf(stdout, "[LOG][%s] certificate is valid.\n", __func__);
		ret = DPS_OPERATION_SUCCESS;
	}

	/* verify signature */
	if((ret = cert_svc_verify_signature(ctx, msg, msglen, sig, "SHA256", &val_sig)) != CERT_SVC_ERR_NO_ERROR) {
		fprintf(stderr, "[ERR][%s] Fail to verify signature, [%d]\n", __func__, ret);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	if(val_sig != 1) { // fail
		fprintf(stdout, "[LOG][%s] signature is not valid.\n", __func__);
		ret = DPS_INVALID_OPERATION;
		goto err;
	}
	else {	// success
		fprintf(stdout, "[LOG][%s] signature is valid.\n", __func__);
		ret = DPS_OPERATION_SUCCESS;
	}

err:
	if(fp_deb != NULL) fclose(fp_deb);
	if(fp_sig != NULL) fclose(fp_sig);

	if(msg != NULL) free(msg);
	if(sig != NULL) free(sig);
	if(cert != NULL) free(cert);
	if(target_info != NULL)	free(target_info);

	cert_svc_cert_context_final(ctx);
	
	return ret;
}

int main(int argc, char* argv[])
{
	int ret = DPS_OPERATION_SUCCESS;

	if(argc < 2) {
		fprintf(stderr, "[ERR] Check your argument!!\n");
		print_usage();
		return 0;
	}
	
	if(!strncmp(argv[1], "gencert", 7))
		ret = generate_sdk_cert(argc - 2, (const char **)argv + 2);
	else if(!strncmp(argv[1], "sign", 4))
		ret = package_sign(argc - 2, (const char **)argv + 2);
	else if(!strncmp(argv[1], "verify", 6))
		ret = package_verify(argc - 2, (const char **)argv + 2);
	else if(!strncmp(argv[1], "help", 4))
		print_usage();
	else {
		fprintf(stderr, "[ERR] Check your argument!!\n");
		print_usage();
	}

	fprintf(stderr, "return: [%d]\n", ret);
	
	return 1;
}
