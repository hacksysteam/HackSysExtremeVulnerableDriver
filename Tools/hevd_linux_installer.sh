#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "❗ Usage: $0 {install|uninstall}"
    exit 1
fi

CURRENT_DIR=${PWD}
BUILD_ARCH=x64
PROJECT_NAME=hevd
PROJECT_ROOT="$(readlink -f ${CURRENT_DIR}/../)"
BUILD_DIR="${PROJECT_ROOT}/build/driver/linux/vulnerable/${BUILD_ARCH}"
MODULE_PATH="${BUILD_DIR}/${PROJECT_NAME}.ko"
HEVD_DEVICE_PATH="/dev/HackSysExtremeVulnerableDriver"

# Run this script as root
if [ "$(id -u)" != "0" ]; then
    echo "🚫 This script must be run as root"
    exit 1
fi

if [ ! -f "${MODULE_PATH}" ]; then
    echo "🔍 Kernel module not found: ${MODULE_PATH}"
    exit 1
fi

case "$1" in
    install)
        # Load the kernel module
        insmod "${MODULE_PATH}"

        if [ $? -eq 0 ]; then
            echo "✅ Kernel module loaded successfully"

            # Change the permissions of the device file
            sleep 1
            chmod a+rw "${HEVD_DEVICE_PATH}"
            echo "🔒 Permissions updated: ${HEVD_DEVICE_PATH}"
        else
            echo "❌ Failed to load kernel module: ${MODULE_PATH}"
            exit 1
        fi
        ;;
    uninstall|remove)
        # Unload the kernel module
        rmmod "${PROJECT_NAME}"

        if [ $? -eq 0 ]; then
            echo "✅ Kernel module unloaded successfully"
        else
            echo "❌ Failed to unload kernel module: ${PROJECT_NAME}"
            exit 1
        fi
        ;;
    *)
        echo "❗ Invalid option: $1"
        echo "❗ Usage: $0 {install|uninstall}"
        exit 1
        ;;
esac
