/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        XmlsecAdapter.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     2.0
 * @brief
 */
#include <cstdlib>
#include <cstring>
#include <functional>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#endif

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <xmlsec/io.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/errors.h>

#include <dpl/assert.h>
#include <dpl/log/log.h>
#include <dpl/singleton_impl.h>

#include <vcore/XmlsecAdapter.h>

IMPLEMENT_SINGLETON(ValidationCore::XmlSec)

namespace {

template <typename Type>
struct CustomPtr {
    Type ptr;
    std::function<void(Type)> deleter;

    CustomPtr() = delete;

    explicit CustomPtr(Type in, std::function<void(Type)> d)
        : ptr(in)
        , deleter(d) {}

    ~CustomPtr()
    {
        deleter(ptr);
    }

    inline Type get(void) const
    {
        return ptr;
    }

    inline Type operator->() const
    {
        return ptr;
    }

    inline bool operator!() const
    {
        return (ptr == nullptr) ? true : false;
    }
};

struct FileWrapper {
    FileWrapper(void *argFile, bool argReleased)
      : file(argFile)
      , released(argReleased)
    {}
    void *file;
    bool released;
};

} // anonymous namespace

namespace ValidationCore {

static const std::string DIGEST_MD5 = "md5";

std::string XmlSec::s_prefixPath;

int XmlSec::fileMatchCallback(const char *filename)
{
    std::string path = s_prefixPath + filename;

    return xmlFileMatch(path.c_str());
}

void *XmlSec::fileOpenCallback(const char *filename)
{
    std::string path = s_prefixPath + filename;

    LogDebug("Xmlsec opening : " << path);
    return new FileWrapper(xmlFileOpen(path.c_str()), false);
}

int XmlSec::fileReadCallback(void *context,
        char *buffer,
        int len)
{
    FileWrapper *fw = static_cast<FileWrapper*>(context);
    if (fw->released)
        return 0;

    int output = xmlFileRead(fw->file, buffer, len);
    if (output == 0) {
        fw->released = true;
        xmlFileClose(fw->file);
    }

    return output;
}

int XmlSec::fileCloseCallback(void *context)
{
    FileWrapper *fw = static_cast<FileWrapper*>(context);
    int output = 0;
    if (!fw->released)
        output = xmlFileClose(fw->file);

    delete fw;

    return output;
}

void XmlSec::fileExtractPrefix(XmlSecContext &context)
{
    if (!context.workingDirectory.empty()) {
        s_prefixPath = context.workingDirectory;
        return;
    }

    s_prefixPath = context.signatureFile;
    size_t pos = s_prefixPath.rfind('/');
    if (pos == std::string::npos)
        s_prefixPath.clear();
    else
        s_prefixPath.erase(pos + 1, std::string::npos);
}

void LogDebugPrint(const char *file,
                   int line,
                   const char *func,
                   const char *errorObject,
                   const char *errorSubject,
                   int reason,
                   const char *msg)
{
    std::stringstream ss;
    ss << "[" << file << ":" << line << "][" << func
        << "] : [" << errorObject << "] : [" << errorSubject
        << "] : [" << msg << "]" << std::endl;

    if (reason == 256)
        LogError(ss.str());
    else
        LogDebug(ss.str());
}

XmlSec::XmlSec()
    : m_initialized(false)
    , m_pList(nullptr)
{
    LIBXML_TEST_VERSION
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1;
#endif

    if (xmlSecInit() < 0)
        ThrowMsg(Exception::InternalError, "Xmlsec initialization failed.");

    if (xmlSecCheckVersion() != 1) {
        xmlSecShutdown();
        ThrowMsg(Exception::InternalError,
                 "Loaded xmlsec library version is not compatible.");
    }

#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
        xmlSecShutdown();
        LogError(
            "Error: unable to load default xmlsec-crypto library. Make sure "
            "that you have it installed and check shared libraries path "
            "(LD_LIBRARY_PATH) envornment variable.");
        ThrowMsg(Exception::InternalError,
                 "Unable to load default xmlsec-crypto library.");
    }
#endif

    if (xmlSecCryptoAppInit(nullptr) < 0) {
        xmlSecShutdown();
        ThrowMsg(Exception::InternalError, "Crypto initialization failed.");
    }

    if (xmlSecCryptoInit() < 0) {
        xmlSecCryptoAppShutdown();
        xmlSecShutdown();
        ThrowMsg(Exception::InternalError,
                 "Xmlsec-crypto initialization failed.");
    }

    m_initialized = true;
}

XmlSec::~XmlSec()
{
    if (m_initialized)
        return;

    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();

#ifndef XMLSEC_NO_XSLT
    xsltCleanupGlobals();
#endif

    s_prefixPath.clear();
    m_initialized = false;
}

void XmlSec::validateFile(XmlSecContext &context, xmlSecKeysMngrPtr mngrPtr)
{
    fileExtractPrefix(context);
    LogDebug("Prefix path : " << s_prefixPath);

    xmlSecIOCleanupCallbacks();

    xmlSecIORegisterCallbacks(
        fileMatchCallback,
        fileOpenCallback,
        fileReadCallback,
        fileCloseCallback);

    CustomPtr<xmlDocPtr> docPtr(xmlParseFile(context.signatureFile.c_str()), xmlFreeDoc);
    if (!docPtr || xmlDocGetRootElement(docPtr.get()) == nullptr)
        ThrowMsg(Exception::InvalidFormat,
                "Unable to parse sig xml file: " << context.signatureFile);

    xmlNodePtr node = xmlSecFindNode(
            xmlDocGetRootElement(docPtr.get()),
            xmlSecNodeSignature,
            xmlSecDSigNs);
    if (node == nullptr)
        ThrowMsg(Exception::InvalidFormat,
                "Start node not found in " << context.signatureFile);

    CustomPtr<xmlSecDSigCtxPtr> dsigCtx(xmlSecDSigCtxCreate(mngrPtr), xmlSecDSigCtxDestroy);
    if (!dsigCtx)
        ThrowMsg(Exception::OutOfMemory, "Failed to create signature context.");

    if (context.allowBrokenChain)
        dsigCtx->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_ALLOW_BROKEN_CHAIN;

    if (context.validationTime) {
        LogDebug("Setting validation time.");
        dsigCtx->keyInfoReadCtx.certsVerificationTime = context.validationTime;
    }

    int res;
    switch (m_mode) {
    case ValidateMode::NORMAL:
        res = xmlSecDSigCtxVerify(dsigCtx.get(), node);
        break;

    case ValidateMode::NO_HASH:
        res = xmlSecDSigCtxVerifyEx(dsigCtx.get(), node, 1, nullptr);
        break;

    case ValidateMode::PARTIAL_HASH:
    {
        size_t n = m_pList->size();
        const char *pList[n + 1] = {0};

        size_t i = 0;
        for (auto uri : *m_pList)
            pList[i++] = uri.c_str();

        res = xmlSecDSigCtxVerifyEx(dsigCtx.get(), node, 0, pList);
        break;
    }
    default:
        ThrowMsg(Exception::InternalError, "ValidateMode is invalid");
    }

    if (res != 0)
        ThrowMsg(Exception::InvalidSig, "Signature verify error.");

    if (dsigCtx->keyInfoReadCtx.flags2 & XMLSEC_KEYINFO_ERROR_FLAGS_BROKEN_CHAIN) {
        LogWarning("Signature contains broken chain!");
        context.errorBrokenChain = true;
    }

    if (dsigCtx->status != xmlSecDSigStatusSucceeded)
        ThrowMsg(Exception::InvalidSig, "Signature status is not succedded.");

    xmlSecSize refSize = xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));
    for (xmlSecSize i = 0; i < refSize; ++i) {
        xmlSecDSigReferenceCtxPtr dsigRefCtx = static_cast<xmlSecDSigReferenceCtxPtr>(
                xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), i));

        if (!dsigRefCtx || !dsigRefCtx->uri)
            continue;

        if (dsigRefCtx->digestMethod
            && dsigRefCtx->digestMethod->id
            && dsigRefCtx->digestMethod->id->name) {
            auto digest = reinterpret_cast<const char * const>(
                    dsigRefCtx->digestMethod->id->name);

            if (DIGEST_MD5.compare(digest) == 0)
                ThrowMsg(Exception::InvalidFormat,
                        "MD5 digest method used! Please use sha");
        }

        context.referenceSet.emplace(reinterpret_cast<char *>(dsigRefCtx->uri));
    }
}

void XmlSec::loadDERCertificateMemory(XmlSecContext &context, xmlSecKeysMngrPtr mngrPtr)
{
    std::string derCert;

    try {
        derCert = context.certificatePtr->getDER();
    } catch (Certificate::Exception::Base &e) {
        ThrowMsg(Exception::InternalError,
                 "Failed during x509 conversion to der format: " << e.DumpToString());
    }

    if (xmlSecCryptoAppKeysMngrCertLoadMemory(
            mngrPtr,
            reinterpret_cast<const xmlSecByte *>(derCert.data()),
            static_cast<xmlSecSize>(derCert.length()),
            xmlSecKeyDataFormatDer,
            xmlSecKeyDataTypeTrusted) < 0)
        ThrowMsg(Exception::InternalError, "Failed to load der cert from memory.");
}

void XmlSec::loadPEMCertificateFile(XmlSecContext &context, xmlSecKeysMngrPtr mngrPtr)
{
    if (xmlSecCryptoAppKeysMngrCertLoad(
            mngrPtr,
            context.certificatePath.c_str(),
            xmlSecKeyDataFormatPem,
            xmlSecKeyDataTypeTrusted) < 0)
        ThrowMsg(Exception::InternalError, "Failed to load PEM cert from file.");
}

void XmlSec::validateInternal(XmlSecContext &context)
{
    LogDebug("Start to validate.");
    Assert(!context.signatureFile.empty());
    Assert(!!context.certificatePtr || !context.certificatePath.empty());

    xmlSecErrorsSetCallback(LogDebugPrint);

    if (!m_initialized)
        ThrowMsg(Exception::InternalError, "XmlSec is not initialized");

    CustomPtr<xmlSecKeysMngrPtr> mngrPtr(xmlSecKeysMngrCreate(), xmlSecKeysMngrDestroy);

    if (!mngrPtr)
        ThrowMsg(Exception::InternalError, "Failed to create keys manager.");

    if (xmlSecCryptoAppDefaultKeysMngrInit(mngrPtr.get()) < 0)
        ThrowMsg(Exception::InternalError, "Failed to initialize keys manager.");

    context.referenceSet.clear();

    if (!!context.certificatePtr)
        loadDERCertificateMemory(context, mngrPtr.get());

    if (!context.certificatePath.empty())
        loadPEMCertificateFile(context, mngrPtr.get());

    validateFile(context, mngrPtr.get());
}

void XmlSec::validate(XmlSecContext &context)
{
    m_mode = ValidateMode::NORMAL;
    validateInternal(context);
}

void XmlSec::validateNoHash(XmlSecContext &context)
{
    m_mode = ValidateMode::NO_HASH;
    validateInternal(context);
}

void XmlSec::validatePartialHash(XmlSecContext &context, const std::list<std::string> &targetUri)
{
    m_mode = ValidateMode::PARTIAL_HASH;
    m_pList = &targetUri;

    validateInternal(context);
}

} // namespace ValidationCore
