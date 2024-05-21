# Copyright (c) 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT
# Helper script to setup the environment for compiling the OPTIGA™ - Zephyr examples.
#
# Tasks:
# * Clone the OPTIGA™ repository from GitHub (https://github.com/Infineon/optiga-trust-m.git)
# * Optionally install the Zephyr environment as described by the "Getting Started Guide" (https://docs.zephyrproject.org/latest/develop/getting_started/)
#
# Force the user to execute the script with 'source' to keep the environment enabled after it exits.
# Copied from zephyr-env.sh
if [ -n "${ZSH_VERSION:-}" ]; then
	dir="${(%):-%N}"
	if [ $options[posixargzero] != "on" ]; then
		setopt posixargzero
		name=$(basename -- "$0")
		unsetopt posixargzero
	else
		name=$(basename -- "$0")
	fi
else
	dir="${BASH_SOURCE[0]}"
	name=$(basename -- "$0")
fi

if [ "X$name" "==" "Xinstall.sh" ]; then
    echo "Source this file (do NOT execute it!) to set the Zephyr Kernel environment:"
    echo ":> source optiga-trust-m-zephyr/scripts/install.sh"
    return 0
fi

if [ ! -d "optiga-trust-m-zephyr" ]; then
    echo "Invalid location, you need to run install.sh from the project root directory:"
    echo ":> source optiga-trust-m-zephyr/scripts/install.sh"
    return 0
fi

# Initialize OPTIGA™ Trust-M files
git clone --recurse-submodules https://github.com/Infineon/optiga-trust-m.git

# Setup Zephyr Environment
if [ -z $VIRTUAL_ENV ]; then
    echo "Initializing Python Virtual Environment."
    python3 -m venv ./zephyrproject/.venv
    source ./zephyrproject/.venv/bin/activate
    pip install west
else
    echo "Virtual environment active, skipping initialization."
fi

if [ -z $ZEPHYR_BASE ]; then
    echo "Installing Zephyr Environment."
    west init ./zephyrproject
    cd ./zephyrproject
    west update
    west zephyr-export
    pip install -r ./zephyr/scripts/requirements.txt
    export ZEPHYR_BASE=$(pwd)/zephyr
    cd ..

    echo ""
    echo "Zephyr environment configured."
    echo ""
    echo "---------------------------------------------------------------------------------------------------------------------------------------------------"
    echo "WARNING: Zephyr SDK needs to be installed manually! (https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html#toolchain-zephyr-sdk)"
    echo "---------------------------------------------------------------------------------------------------------------------------------------------------"
    echo ""
else
    echo "Zephyr environment found at '$ZEPHYR_BASE', skipping initialization."
fi