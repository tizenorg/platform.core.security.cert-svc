PKG_CHECK_MODULES(VCORE_DEPS
    REQUIRED
    libxml-2.0
    libpcrecpp
    openssl
    xmlsec1
    dlog
    libsystemd-journal
    )

ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS})
ADD_DEFINITIONS(${VCORE_DEPS_CFLAGS_OTHER})

SET(VCORE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

SET(VCORE_SOURCES
    ${VCORE_DIR}/dpl/core/src/assert.cpp
    ${VCORE_DIR}/dpl/core/src/exception.cpp
    ${VCORE_DIR}/dpl/core/src/noncopyable.cpp
    ${VCORE_DIR}/dpl/core/src/singleton.cpp
    ${VCORE_DIR}/dpl/core/src/colors.cpp

    ${VCORE_DIR}/dpl/log/src/abstract_log_provider.cpp
    ${VCORE_DIR}/dpl/log/src/old_style_log_provider.cpp
    ${VCORE_DIR}/dpl/log/src/dlog_log_provider.cpp
    ${VCORE_DIR}/dpl/log/src/journal_log_provider.cpp
    ${VCORE_DIR}/dpl/log/src/log.cpp

    ${VCORE_DIR}/vcore/api.cpp
    ${VCORE_DIR}/vcore/Base64.cpp
    ${VCORE_DIR}/vcore/Certificate.cpp
    ${VCORE_DIR}/vcore/CertificateCollection.cpp
    ${VCORE_DIR}/vcore/CertificateConfigReader.cpp
    ${VCORE_DIR}/vcore/CertificateLoader.cpp
    ${VCORE_DIR}/vcore/CertStoreType.cpp
    ${VCORE_DIR}/vcore/ReferenceValidator.cpp
    ${VCORE_DIR}/vcore/SaxReader.cpp
    ${VCORE_DIR}/vcore/SignatureData.cpp
    ${VCORE_DIR}/vcore/SignatureFinder.cpp
    ${VCORE_DIR}/vcore/SignatureReader.cpp
    ${VCORE_DIR}/vcore/TimeConversion.cpp
    ${VCORE_DIR}/vcore/ValidatorFactories.cpp
    ${VCORE_DIR}/vcore/SignatureValidator.cpp
    ${VCORE_DIR}/vcore/XmlsecAdapter.cpp
    ${VCORE_DIR}/vcore/pkcs12.cpp
    ${VCORE_DIR}/vcore/exception.cpp
    ${VCORE_DIR}/vcore/Client.cpp
    ${VCORE_DIR}/vcore/Ocsp.cpp
    ${VCORE_DIR}/vcore/CryptoInit.cpp
    )

SET(VCORE_INCLUDES
    ${VCORE_DIR}/dpl/core/include
    ${VCORE_DIR}/dpl/log/include
    ${VCORE_DIR}
    )

########### VCORE SOURCES ########

INCLUDE_DIRECTORIES(
    SYSTEM
    ${VCORE_DEPS_INCLUDE_DIRS}
    ${VCORE_INCLUDES}
    )

ADD_LIBRARY(${TARGET_VCORE_LIB} SHARED ${VCORE_SOURCES})

# TODO: visibility needed to be hidden
SET_TARGET_PROPERTIES(${TARGET_VCORE_LIB}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${SO_VERSION}
        VERSION ${VERSION})

TARGET_LINK_LIBRARIES(${TARGET_VCORE_LIB}
    ${VCORE_DEPS_LIBRARIES}
    ${TARGET_CERT_SVC_LIB}
    )

########## cert-server #############
PKG_CHECK_MODULES(CERT_SERVER_DEP
    REQUIRED
    dlog
    sqlite3
    db-util
    libsystemd-daemon
    key-manager
    )

SET(CERT_SERVER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/server)

SET(CERT_SERVER_SRC
    ${CERT_SERVER_DIR}/src/cert-server-main.c
    ${CERT_SERVER_DIR}/src/cert-server-logic.c
    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${CERT_SERVER_DEP_INCLUDE_DIRS}
    ${VCORE_DIR}
    ${CERT_SERVER_DIR}/include
    )

SET_SOURCE_FILES_PROPERTIES(
    ${CERT_SERVER_SRC}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE"
    )

ADD_EXECUTABLE(${TARGET_CERT_SERVER} ${CERT_SERVER_SRC})

TARGET_LINK_LIBRARIES(${TARGET_CERT_SERVER}
    ${CERT_SERVER_DEP_LIBRARIES}
    -pie
    )

INSTALL(TARGETS ${TARGET_CERT_SERVER} DESTINATION ${TZ_SYS_BIN})

########################################################
INSTALL(TARGETS ${TARGET_VCORE_LIB}
    DESTINATION ${LIBDIR}
    )

INSTALL(FILES
    ${VCORE_DIR}/vcore/SignatureValidator.h
    ${VCORE_DIR}/vcore/SignatureFinder.h
    ${VCORE_DIR}/vcore/Certificate.h
    ${VCORE_DIR}/vcore/SignatureData.h
    ${VCORE_DIR}/vcore/CertStoreType.h
    ${VCORE_DIR}/vcore/exception.h
    DESTINATION ${INCLUDEDIR}/cert-svc/vcore
    )

INSTALL(FILES
    ${VCORE_DIR}/cert-svc/ccert.h
    ${VCORE_DIR}/cert-svc/cinstance.h
    ${VCORE_DIR}/cert-svc/cerror.h
    ${VCORE_DIR}/cert-svc/cpkcs12.h
    ${VCORE_DIR}/cert-svc/cprimitives.h
    ${VCORE_DIR}/cert-svc/cstring.h
    DESTINATION ${INCLUDEDIR}/cert-svc/cert-svc
    )
