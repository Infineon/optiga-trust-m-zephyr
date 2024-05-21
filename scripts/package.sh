# Copyright (c) 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

# This script creates an archive of the optiga test-application with the Zephyr PAL.
# Allows fast creation of code drops until the relevant code is merged to upstream repositories.
# Needs to be called from within the 'scripts' directory to use correct relative paths.

PACKAGE_DIR=../build/dist/OPTIGA-TRUST-M-ZEPHYR
if [ ! -d "../scripts" ]; then
  echo "Invalid location, you need to run package.sh from the 'scripts' directory."
  exit 1
fi

mkdir -p $PACKAGE_DIR
rsync -av --progress --exclude="build" --exclude=".git" ../ $PACKAGE_DIR/optiga-trust-m-app

cd $PACKAGE_DIR/../
zip -r OPTIGA-Trust-M-Zephyr-Package.zip ./OPTIGA-TRUST-M-ZEPHYR
