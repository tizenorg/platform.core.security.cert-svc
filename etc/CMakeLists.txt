
SET(ETC_DIR ${PROJECT_SOURCE_DIR}/etc)

  INSTALL(FILES
    ${ETC_DIR}/cert_svc_create_clean_db.sh
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )

INSTALL(FILES
    ${ETC_DIR}/schema.xsd
    DESTINATION /usr/share/cert-svc/
    )

INSTALL(FILES
    ${ETC_DIR}/fingerprint_list.xsd
    DESTINATION /usr/share/cert-svc/
    )

INSTALL(FILES
    ${ETC_DIR}/fingerprint_list.xml
    DESTINATION /usr/share/cert-svc/
    )

ADD_SUBDIRECTORY(certificates)
