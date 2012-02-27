CC ?= gcc

TARGETS = \
		  utc_SecurityFW_cert_svc_load_buf_to_context_func \
		  utc_SecurityFW_cert_svc_load_file_to_context_func \
  		  utc_SecurityFW_cert_svc_load_PFX_file_to_context_func \
		  utc_SecurityFW_cert_svc_push_buf_into_context_func \
		  utc_SecurityFW_cert_svc_push_file_into_context_func \
		  utc_SecurityFW_cert_svc_add_certificate_to_store_func \
		  utc_SecurityFW_cert_svc_delete_certificate_from_store_func \
		  utc_SecurityFW_cert_svc_verify_certificate_func \
		  utc_SecurityFW_cert_svc_verify_signature_func \
		  utc_SecurityFW_cert_svc_extract_certificate_data_func \
		  utc_SecurityFW_cert_svc_search_certificate_func \
		  utc_SecurityFW_cert_svc_check_ocsp_status_func

PKGS = cert-svc

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGETS) *~
