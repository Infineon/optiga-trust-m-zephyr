<!--
SPDX-FileCopyrightText: 2024 Infineon Technologies AG

SPDX-License-Identifier: MIT
-->

# Quick navigation

- [Quick navigation](#quick-navigation)
- [Project setup](#project-setup)
- [Installation steps](#installation-steps)
- [Manual installation](#manual-installation)
# Project setup
This guide describes the necessary steps to setup the project structure and dependencies:

```
Project root
|__ optiga-trust-m-zephyr   (= Example application)
|__ optiga-trust-m          (= OPTIGA™ Trust M Host Library for C)
|   |__ /extras/pal
|       |__zephyr           (= Zephyr compatible PAL)
|__ zephyrproject
    |__ .west               (= west build workspace)
    |__ .venv               (= Python virtual environment for build toolchain)
```

# Installation steps

1- Create a project root folder (for example : zephyr_root_project).

2- Clone this repository.
```
For example - <Project root>: git clone URL
```
3- An installation script is provided to automatically setup the environments.

> if not installed, A tool might be needed to run the next script in Linux environment. please install dos2unix tool and apply it to the script before running the script.
```
sudo apt install dos2unix
```

The script is tested on Ubuntu (within WSL) and requires the [Zephyr dependencies](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) and GIT to be installed.

An already available Zephyr and Python environment can be used by activating them before calling the script. Otherwise, new environments will be created by the script.

> **WARNING**
The installation script needs to be called from the project root with the following command:

```
<Project root>: dos2unix optiga-trust-m-zephyr/scripts/install.sh
<Project root>: source optiga-trust-m-zephyr/scripts/install.sh
```
> **NOTE**
The script above installs Zephyr and dependencies, **this may take a long time, please be patient, it may look like it is stuck but it is not**.

4- To build and flash the project, please follow the instructions in the [README](../README.md) file.

# Manual installation
The *zephyrproject* directory and the environments will be created during the steps of the [Zephyr Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html).

The latest version of the *OPTIGA™ Trust M Host Library for C* can be [downloaded from GitHub](https://github.com/Infineon/optiga-trust-m).


[def]: #quick-navigation