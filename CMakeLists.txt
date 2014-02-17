CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(certsvc)

INCLUDE(FindPkgConfig)

SET(SO_VERSION 1)
SET(VERSION "${SO_VERSION}.0.0")

# define debug output
SET(DEBUG_OUTPUT "-DCERT_SVC_LOG")             # for debug
#SET(DEBUG_OUTPUT "-DCERT_SVC_LOG_CONSOLE")     # for debug

SET(TARGET_CERT_SVC_LIB "cert-svc")
SET(TARGET_VCORE_LIB "cert-svc-vcore")
SET(TARGET_SIGN_TOOL "dpkg-pki-sig")

# compiler options
SET(GC_SECTIONS_FLAGS "-fdata-sections -ffunction-sections -Wl,--gc-sections")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GC_SECTIONS_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GC_SECTIONS_FLAGS}")

SET(CMAKE_C_FLAGS_RELEASE "-fvisibility=hidden -Wall -O2")
SET(CMAKE_CXX_FLAGS_RELEASE "-std=c++0x -Wall -O2")

SET(CMAKE_C_FLAGS_DEBUG "-fvisibility=hidden -Wall -O0 -g")
SET(CMAKE_CXX_FLAGS_DEBUG "-std=c++0x -Wall -O0 -g")

SET(CMAKE_C_FLAGS_CCOV "-fvisibility=hidden -Wall -O2 --coverage")
SET(CMAKE_CXX_FLAGS_CCOV "-std=c++0x -Wall -O2 --coverage")

SET(CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_SKIP_RPATH "TRUE")
SET(TZ_SYS_SHARE "${TZ_SYS_SHARE}")
SET(TZ_SYS_BIN "${TZ_SYS_BIN}")

################################################################################
# for libcert-svc.so
################################################################################

PKG_CHECK_MODULES(CERT_SVC_DEPS
    openssl
    dlog
    glib-2.0
    REQUIRED
)

SET(CERT_SVC_SOURCES
    ${PROJECT_SOURCE_DIR}/srcs/cert-service.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-util.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-store.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-process.c
)

IF(DEFINED DEBUG_OUTPUT)
    SET_SOURCE_FILES_PROPERTIES(${CERT_SVC_SOURCES}
        PROPERTIES COMPILE_FLAGS ${DEBUG_OUTPUT})
ENDIF(DEFINED DEBUG_OUTPUT)

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include
    ${CERT_SVC_DEPS_INCLUDE_DIRS}
)

ADD_LIBRARY(${TARGET_CERT_SVC_LIB} SHARED ${CERT_SVC_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_CERT_SVC_LIB} PROPERTIES
    SOVERSION ${SO_VERSION}
    VERSION ${VERSION}
)

TARGET_LINK_LIBRARIES(${TARGET_CERT_SVC_LIB}
    pthread
    ${CERT_SVC_DEPS_LIBRARIES}
)

################################################################################
# for dpkg-pki-sig
################################################################################

SET(SIGN_TOOL_SOURCES
    ${PROJECT_SOURCE_DIR}/srcs/dpkg-pki-sig.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-process.c
    ${PROJECT_SOURCE_DIR}/srcs/cert-service-util.c
)

ADD_EXECUTABLE(${TARGET_SIGN_TOOL} ${SIGN_TOOL_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SIGN_TOOL}
    ${TARGET_CERT_SVC_LIB}
    ${CERT_SVC_DEPS_LIBRARIES}
    tzplatform-config-1.0
)

################################################################################

CONFIGURE_FILE(cert-svc.pc.in cert-svc.pc @ONLY)
CONFIGURE_FILE(cert-svc-vcore.pc.in cert-svc-vcore.pc @ONLY)

INSTALL(TARGETS ${TARGET_CERT_SVC_LIB} DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(PROGRAMS ${TARGET_SIGN_TOOL} DESTINATION ${BINDIR})
INSTALL(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cert-svc.pc
    ${CMAKE_CURRENT_BINARY_DIR}/cert-svc-vcore.pc
    DESTINATION ${LIB_INSTALL_DIR}/pkgconfig
)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/targetinfo DESTINATION ${TZ_SYS_SHARE}/cert-svc/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/cert-service.h DESTINATION ${INCLUDEDIR})

# Now we must create empty directory for certificates.
# Without this directories rpm package will fail during build.
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /usr/share/cert-svc/ca-certs/code-signing/native
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /usr/share/cert-svc/ca-certs/code-signing/wac
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/code-signing/wac
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/code-signing/tizen
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/sim/operator
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/sim/thirdparty
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/user
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/trusteduser
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/mdm/security
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/certs/mdm/security/cert
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/pkcs12
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)

ADD_SUBDIRECTORY(vcore)
ADD_SUBDIRECTORY(etc)