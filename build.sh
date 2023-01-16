#!/bin/sh
echo "Starting build"
cargo build --release
echo "Copying assets to target"
cp -r assets target/release
echo "Finished build"