#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)
COMPONENT_ADD_INCLUDEDIRS := .
# embed files from the "certs" directory as binary data symbols
# in the app
COMPONENT_EMBED_TXTFILES := acct_key.pem
