SET(ETC_DIR ${PROJECT_SOURCE_DIR}/etc)

INSTALL(FILES
    ${ETC_DIR}/schema.xsd
    DESTINATION ${TZ_SYS_RO_WRT_ENGINE}
    )

INSTALL(FILES
    ${ETC_DIR}/make-ca-certificate.sh
    DESTINATION ${TZ_SYS_BIN}
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
    )


IF (DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)
INSTALL(FILES
    ${ETC_DIR}/cert_svc_create_clean_db.sh
    DESTINATION ${TZ_SYS_BIN}
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
    )

INSTALL(FILES
    ${ETC_DIR}/cert_svc_vcore_db.sql
    DESTINATION ${TZ_SYS_SHARE}/cert-svc
    )
ENDIF (DEFINED TIZEN_FEAT_CERTSVC_OCSP_CRL)


INSTALL(FILES
    ${ETC_DIR}/initialize_store_db.sh
    ${ETC_DIR}/cert_svc_create_clean_store_db.sh
    DESTINATION ${TZ_SYS_BIN}
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
    )

INSTALL(FILES
    ${ETC_DIR}/cert_svc_store_db.sql
    DESTINATION ${TZ_SYS_SHARE}/cert-svc
    )
