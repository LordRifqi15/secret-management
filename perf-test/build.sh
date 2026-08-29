#!/bin/zsh
# Build the Go application
go mod tidy
go build -o perf-test perf-test.go

#if success then show message build success if not then show message build failed
if [ $? -eq 0 ]; then
    echo "Build successful!"
else
    echo "Build failed!"
    exit 1
fi