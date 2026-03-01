#!/bin/bash
set -e

# This script assumes that test-neverbleed has already been built.

PORT=8888
CRT=t/assets/test.crt
KEY=t/assets/test.key

# Start the test server in background
./test-neverbleed privsep $PORT $CRT $KEY > test.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
SUCCESS=0
for i in {1..20}; do
    if lsof -i :$PORT > /dev/null; then
        SUCCESS=1
        break
    fi
    sleep 0.5
done

if [ $SUCCESS -ne 1 ]; then
    echo "Server failed to start!"
    cat test.log
    kill $SERVER_PID || true
    exit 1
fi

# Verify handshake with s_client
echo -e "GET / HTTP/1.0\r\n\r\n" | openssl s_client -connect 127.0.0.1:$PORT -CAfile $CRT -verify_return_error -ign_eof > s_client.out 2>&1

# Check if successful
if grep -q "Verification: OK" s_client.out && grep -q "HTTP/1.0 200 OK" s_client.out && grep -q "hello" s_client.out; then
    echo "Handshake and request successful!"
    result=0
else
    echo "Handshake or request failed!"
    echo "--- s_client output ---"
    cat s_client.out
    echo "--- server log ---"
    cat test.log
    result=1
fi

# Kill server
kill $SERVER_PID || true
wait $SERVER_PID 2>/dev/null || true

# Cleanup logs only on success
if [ $result -eq 0 ]; then
    rm test.log s_client.out
fi

exit $result
