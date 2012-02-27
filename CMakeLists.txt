CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(certsvc C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION_MAJOR 1)
SET(VERSION "${VERSION_MAJOR}.0.0")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED openssl dlog)

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
TARGET_LINK_LIBRARIES(cert-svc ${pkgs_LDFLAGS} -L${prefix}/lib -lpthread)
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

INSTALL(TARGETS cert-svc DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/dpkg-pki-sig DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/cert-svc.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/targetinfo DESTINATION /opt/share/cert-svc/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/cert-service.h DESTINATION include)
