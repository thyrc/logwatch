#!/bin/bash

# install stuff needed for the `script` phase

# Where rustup gets installed.
export PATH="$PATH:$HOME/.cargo/bin"

set -ex

. "$(dirname $0)/utils.sh"

install_rustup() {
    curl https://sh.rustup.rs -sSf \
      | sh -s -- -y --default-toolchain "$TRAVIS_RUST_VERSION"
    rustc -Vv
    cargo -Vv
}

install_rustfmt() {
    rustup component add rustfmt
}

install_musltools() {
    if $(is_musl); then
        apt-get -y install musl-tools
    fi
}

install_targets() {
    if [ $(host) != "$TARGET" ]; then
        rustup target add $TARGET
    fi
}

main() {
    install_rustup
    install_targets
    install_musltools
    install_rustfmt
}

main
