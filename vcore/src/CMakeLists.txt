# == customized for cert-svc build script ==
SET(API_VERSION ${VERSION_MAJOR})
# ==========================================

INCLUDE(FindPkgConfig)

PKG_CHECK_MODULES(VCORE_DEPS
    dpl-efl
    dpl-db-efl
    ecore
    appcore-efl
    libxml-2.0
    libsoup-2.4
    libpcre
    libpcrecpp
    openssl
    xmlsec1
    secure-storage
    REQUIRED)

SET(VCORE_DIR
    ${PROJECT_SOURCE_DIR}/vcore
    )

SET(VCORE_SRC_DIR
    ${VCORE_DIR}/src/vcore
    )

SET(VCORE_SOURCES
    ${VCORE_SRC_DIR}/api.cpp
    ${VCORE_SRC_DIR}/Base64.cpp
    ${VCORE_SRC_DIR}/CachedCRL.cpp
    ${VCORE_SRC_DIR}/CachedOCSP.cpp
    ${VCORE_SRC_DIR}/Certificate.cpp
    ${VCORE_SRC_DIR}/CertificateCacheDAO.cpp
    ${VCORE_SRC_DIR}/CertificateCollection.cpp
    ${VCORE_SRC_DIR}/CertificateConfigReader.cpp
    ${VCORE_SRC_DIR}/CertificateLoader.cpp
    ${VCORE_SRC_DIR}/CertificateVerifier.cpp
    ${VCORE_SRC_DIR}/Config.cpp
    ${VCORE_SRC_DIR}/CRL.cpp
    ${VCORE_SRC_DIR}/CRLCacheDAO.cpp
    ${VCORE_SRC_DIR}/Database.cpp
    ${VCORE_SRC_DIR}/DeveloperModeValidator.cpp
    ${VCORE_SRC_DIR}/OCSP.cpp
    ${VCORE_SRC_DIR}/OCSPCertMgrUtil.cpp
    ${VCORE_SRC_DIR}/OCSPUtil.c
    ${VCORE_SRC_DIR}/ReferenceValidator.cpp
    ${VCORE_SRC_DIR}/RevocationCheckerBase.cpp
    ${VCORE_SRC_DIR}/SaxReader.cpp
    ${VCORE_SRC_DIR}/SignatureFinder.cpp
    ${VCORE_SRC_DIR}/SignatureReader.cpp
    ${VCORE_SRC_DIR}/SignatureValidator.cpp
    ${VCORE_SRC_DIR}/SoupMessageSendBase.cpp
    ${VCORE_SRC_DIR}/SoupMessageSendSync.cpp
    ${VCORE_SRC_DIR}/SoupMessageSendAsync.cpp
    ${VCORE_SRC_DIR}/VerificationStatus.cpp
    ${VCORE_SRC_DIR}/ValidatorFactories.cpp
    ${VCORE_SRC_DIR}/VCore.cpp
    ${VCORE_SRC_DIR}/XmlsecAdapter.cpp
    ${VCORE_SRC_DIR}/pkcs12.c
    )

SET(VCORE_INCLUDES
    ${VCORE_DEPS_INCLUDE_DIRS}
    ${VCORE_SRC_DIR}
    ${VCORE_DIR}/src
    ${VCORE_DIR}/src/orm
    ${VCORE_DIR}/src/legacy
    ${CMAKE_BINARY_DIR}/vcore/src
    )

ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS})
ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS_OTHER})
ADD_DEFINITIONS("-DSEPARATED_SINGLETON_IMPLEMENTATION")
ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")

INCLUDE_DIRECTORIES(${VCORE_INCLUDES})

# cert-svc headers
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)

ADD_LIBRARY(${TARGET_VCORE_LIB} SHARED ${VCORE_SOURCES})
SET_TARGET_PROPERTIES(${TARGET_VCORE_LIB} PROPERTIES
    SOVERSION ${API_VERSION}
    VERSION ${VERSION})

ADD_DEPENDENCIES(${TARGET_VCORE_LIB} Sqlite3DbWTF)

SET_TARGET_PROPERTIES(${TARGET_VCORE_LIB} PROPERTIES
  COMPILE_FLAGS -fPIC)

TARGET_LINK_LIBRARIES(${TARGET_VCORE_LIB}
    ${VCORE_DEPS_LIBRARIES}
    cert-svc
  )

INSTALL(TARGETS ${TARGET_VCORE_LIB}
    DESTINATION /usr/lib
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
    )

INSTALL(FILES
    ${VCORE_SRC_DIR}/Base64.h
    ${VCORE_SRC_DIR}/CachedCRL.h
    ${VCORE_SRC_DIR}/CachedOCSP.h
    ${VCORE_SRC_DIR}/Certificate.h
    ${VCORE_SRC_DIR}/CertificateCacheDAO.h
    ${VCORE_SRC_DIR}/CertificateCollection.h
    ${VCORE_SRC_DIR}/CertificateConfigReader.h
    ${VCORE_SRC_DIR}/CertificateLoader.h
    ${VCORE_SRC_DIR}/CertificateStorage.h
    ${VCORE_SRC_DIR}/CertificateVerifier.h
    ${VCORE_SRC_DIR}/CertStoreType.h
    ${VCORE_SRC_DIR}/Config.h
    ${VCORE_SRC_DIR}/CRL.h
    ${VCORE_SRC_DIR}/Database.h
    ${VCORE_SRC_DIR}/DeveloperModeValidator.h
    ${VCORE_SRC_DIR}/IAbstractResponseCache.h
    ${VCORE_SRC_DIR}/OCSP.h
    ${VCORE_SRC_DIR}/OCSPCertMgrUtil.h
    ${VCORE_SRC_DIR}/ParserSchema.h
    ${VCORE_SRC_DIR}/ReferenceValidator.h
    ${VCORE_SRC_DIR}/RevocationCheckerBase.h
    ${VCORE_SRC_DIR}/SaxReader.h
    ${VCORE_SRC_DIR}/scoped_gpointer.h
    ${VCORE_SRC_DIR}/SignatureData.h
    ${VCORE_SRC_DIR}/SignatureFinder.h
    ${VCORE_SRC_DIR}/SignatureReader.h
    ${VCORE_SRC_DIR}/SignatureValidator.h
    ${VCORE_SRC_DIR}/SoupMessageSendBase.h
    ${VCORE_SRC_DIR}/SoupMessageSendSync.h
    ${VCORE_SRC_DIR}/SoupMessageSendAsync.h
    ${VCORE_SRC_DIR}/SSLContainers.h
    ${VCORE_SRC_DIR}/VerificationStatus.h
    ${VCORE_SRC_DIR}/ValidatorCommon.h
    ${VCORE_SRC_DIR}/ValidatorFactories.h
    ${VCORE_SRC_DIR}/VCore.h
    ${VCORE_SRC_DIR}/XmlsecAdapter.h
    DESTINATION /usr/include/cert-svc/vcore
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
    )

INSTALL(FILES
    ${VCORE_DIR}/src/cert-svc/ccert.h
    ${VCORE_DIR}/src/cert-svc/ccrl.h
    ${VCORE_DIR}/src/cert-svc/cinstance.h
    ${VCORE_DIR}/src/cert-svc/cerror.h
    ${VCORE_DIR}/src/cert-svc/cocsp.h
    ${VCORE_DIR}/src/cert-svc/cpkcs12.h
    ${VCORE_DIR}/src/cert-svc/cprimitives.h
    ${VCORE_DIR}/src/cert-svc/cstring.h
    DESTINATION /usr/include/cert-svc/cert-svc
    PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
    )

#FILE(MAKE_DIRECTORY /opt/share/cert-svc/pkcs12)
