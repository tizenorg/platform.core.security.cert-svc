SET(ETC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

INSTALL(FILES
    ${ETC_DIR}/schema.xsd
    DESTINATION ${TZ_SYS_RO_WRT_ENGINE}
    )

MESSAGE("Add ssl table to certs-meta.db")

EXECUTE_PROCESS(
    COMMAND
        ${ETC_DIR}/cert_svc_create_clean_store_db.sh
        ${ETC_DIR}/cert_svc_store_db.sql
        ${ETC_DIR}/certs-meta.db
    RESULT_VARIABLE ERROR_CODE
    )

IF (ERROR_CODE)
    MESSAGE(FATAL_ERROR "[${ERROR_CODE}] Failed to create clean store db")
ENDIF (ERROR_CODE)

EXECUTE_PROCESS(
    COMMAND
        ${ETC_DIR}/initialize_store_db.sh
        ${ETC_DIR}/certs-meta.db
        ${ETC_DIR}/ca-certificate.crt
    RESULT_VARIABLE ERROR_CODE
    )

IF (ERROR_CODE)
    MESSAGE(FATAL_ERROR "[${ERROR_CODE}] Failed to initialize store db")
ENDIF (ERROR_CODE)

INSTALL(FILES
    ${ETC_DIR}/certs-meta.db
    ${ETC_DIR}/certs-meta.db-journal
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/dbspace
    )

INSTALL(FILES
    ${ETC_DIR}/ca-certificate.crt
    DESTINATION ${TZ_SYS_SHARE}/cert-svc
    )
