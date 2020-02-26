#!/bin/bash

exit 0

# build, test and check formatting in this phase

set -ex

. "$(dirname $0)/utils.sh"

main() {
    CARGO="cargo"

    # normal debug build
    "$CARGO" build --target "$TARGET" --verbose --all

    # Run tests.
    "$CARGO" test --target "$TARGET" --verbose --all

    # Check formatting.
    "$CARGO" fmt --all -- --check
}

main
