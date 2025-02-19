#!/usr/bin/env zsh
gcc multicopy.c -o mcopy -lcrypto -lpthread -lncurses -Wno-deprecated-declarations
cp ./mcopy ~/Desktop
