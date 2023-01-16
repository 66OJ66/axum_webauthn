#!/bin/sh
echo "Starting build"
cargo build --release
echo "Clearing existing assets"
rm -r target/release/assets
echo "Copying assets to target"
cp -r assets target/release
echo "Compressing assets with gzip"
gzip -r -k -9 target/release/assets/
echo "Finished build"