#!/bin/sh

# Key needs to be supplied in hex format
KEYHEX=$(echo -n "YELLOW SUBMARINE" | hexdump -e '16/1 "%02x"')

# Decrypt using AES-ECB and display the plaintext
openssl enc -d -aes-128-ecb -a -in 7.txt -out 7-pt.txt -K $KEYHEX
cat 7-pt.txt
