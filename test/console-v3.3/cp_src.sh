#This script copies mimik library source files and test files needed to
#build esp32 console program with mimik commands for testing

# NOTE: to build esp32 console with mimik service discovery test commands
# all source files that need to be built, should be copied to directory:
# mimik-rtos-sdk/test/console-v3.3/components/cmd_system/

echo
echo "This script simplifies copying needed mimik-rtos-sdk source files for building mimik esp32 console program"
echo "Copying required mimik-rtos-sdk source files to console-v3.3/components/cmd_system directory"
echo

#copy all library source files from mimik-rtos-sdk/src mimik-rtos-sdk/include
cp ../../include/*.h ./components/cmd_system/
cp ../../src/*.c ./components/cmd_system/
cp ../../acme-client/include/*.h ./components/cmd_system/
cp ../../acme-client/src/*.c ./components/cmd_system/

#copy all test source files
cp ../mdns_test_client/*.c ./components/cmd_system/

cp ../../acme-client/test/*.c ./components/cmd_system/
cp ../../acme-client/test/acct_key.pem ./components/cmd_system/

# acct_key.pem  ca_cert.pem  component.mk  mimik_end_to_end_test.c
cp ../mimik_end_to_end_test_client/* ./components/cmd_system/

echo "ls components/cmd_system"
ls ./components/cmd_system/

echo
echo "To build and flash esp32 console:"
echo " - set IDF_PATH environment variable to esp-idf development directory "
echo " - connect esp32 system using usb port "
echo " - Modify any required configuration changes to mimik test programs such as mimik_end_to_end_test.c "
echo " - Run make flash in current console-v3.3/ directory "
echo
