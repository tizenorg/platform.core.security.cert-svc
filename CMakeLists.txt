CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(certsvc)

SET(CMAKE_VERBOSE_MAKEFILE off)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION_MAJOR 1)
SET(VERSION "${VERSION_MAJOR}.0.0")
SET(TARGET_VCORE_LIB "cert-svc-vcore")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED openssl dlog glib-2.0)

FOREACH(flag ${pkgs_CFLAGS})
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(source_dir "./srcs")
SET(include_dir "./include")

# About debug
SET(debug "-DCERT_SVC_LOG")			# for debug
#SET(debug "-DCERT_SVC_LOG_CONSOLE")	# for debug

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_SHARED_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")
SET(CMAKE_SKIP_RPATH "TRUE")
SET(CMAKE_CXX_FLAGS "-O2 -std=c++0x -g -Wall")

###################################################################################################
# for libcert-svc.so
SET(libcert-svc_SOURCES 
		${source_dir}/cert-service.c 
		${source_dir}/cert-service-util.c 
		${source_dir}/cert-service-store.c 
		${source_dir}/cert-service-process.c )
SET(libcert-svc_LDFLAGS " -module -avoid-version ${pkgs_LDFALGS} ")
SET(libcert-svc_CFLAGS " ${CFLAGS} -fvisibility=hidden -g -fPIC -I${CMAKE_CURRENT_SOURCE_DIR}/include ${debug} ")
SET(libcert-svc_CPPFLAGS " -DPIC ")

ADD_LIBRARY(cert-svc SHARED ${libcert-svc_SOURCES})
TARGET_LINK_LIBRARIES(cert-svc ${pkgs_LDFLAGS} ${pkgs_LIBRARIES} -L${prefix}/lib -lpthread)
SET_TARGET_PROPERTIES(cert-svc PROPERTIES COMPILE_FLAGS "${libcert-svc_CFLAGS} ${libcert-svc_CPPFLAGS}")
SET_TARGET_PROPERTIES(cert-svc PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(cert-svc PROPERTIES VERSION ${VERSION})
###################################################################################################

###################################################################################################
# for dpkg-pki-sig
SET(PackageSignVerify_SOURCES
		${source_dir}/dpkg-pki-sig.c
		${source_dir}/cert-service-util.c )
SET(PackageSignVerify_CFLAGS " -fvisibility=hidden -I. -I${CMAKE_CURRENT_SOURCE_DIR}/include ${debug} ")
SET(PackageSignVerify_LDFALGS " -module -avoid-version ${pkgs_LDFLAGS} ")

ADD_EXECUTABLE(dpkg-pki-sig ${PackageSignVerify_SOURCES})
TARGET_LINK_LIBRARIES(dpkg-pki-sig ${pkgs_LDFLAGS} cert-svc)
SET_TARGET_PROPERTIES(dpkg-pki-sig PROPERTIES COMPILE_FLAGS "${PackageSignVerify_CFLAGS} ")
###################################################################################################

CONFIGURE_FILE(cert-svc.pc.in cert-svc.pc @ONLY)
CONFIGURE_FILE(cert-svc-vcore.pc.in cert-svc-vcore.pc @ONLY)

INSTALL(TARGETS cert-svc DESTINATION /usr/lib COMPONENT RuntimeLibraries)
INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/dpkg-pki-sig DESTINATION /usr/bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/cert-svc.pc DESTINATION /usr/lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/cert-svc-vcore.pc DESTINATION /usr/lib/pkgconfig)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/targetinfo DESTINATION /opt/share/cert-svc/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/cert-service.h DESTINATION /usr/include)

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
    DESTINATION /opt/share/cert-svc/certs/code-signing/wac
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/sim/operator
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/sim/thirdparty
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/ssl
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/user
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/trusteduser
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/mdm/security
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)
INSTALL(DIRECTORY ${PROJECT_SOURCE_DIR}/etc/empty
    DESTINATION /opt/share/cert-svc/certs/mdm/security/cert
    FILES_MATCHING PATTERN THISPATTERNMUSTNOTMATCH
)

ADD_SUBDIRECTORY(vcore)
ADD_SUBDIRECTORY(etc)
ADD_SUBDIRECTORY(tests)
