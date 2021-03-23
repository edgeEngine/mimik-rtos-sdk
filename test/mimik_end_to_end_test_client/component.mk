
COMPONENT_ADD_INCLUDEDIRS := .

# embed files as binary data symbols
COMPONENT_EMBED_TXTFILES := acct_key.pem
COMPONENT_EMBED_TXTFILES += ca_cert.pem

#Define ENABLE_BUILDTIME_EMBED_CLIENT_CERT_PEM_FILE to enable embed client_cert.pem at build time
#COMPONENT_EMBED_TXTFILES += client_cert.pem

#Define ENABLE_BUILDTIME_EMBED_CLIENT_KEY_PEM_FILE to enable embed client_key.pem at build time
#COMPONENT_EMBED_TXTFILES += client_key.pem
