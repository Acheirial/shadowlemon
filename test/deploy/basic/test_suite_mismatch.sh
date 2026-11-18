#!/bin/bash

# Copyright (C) 2026  mieru authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Make sure this script has executable permission:
# git update-index --chmod=+x <file>

set -e

# Load test library.
source ./libtest.sh

# Deployment level test of a cipher suite set mismatch: the server allows
# CIPHER_SUITE_AES_128_GCM only (server_suite_mismatch.json) and the client
# offers CIPHER_SUITE_XCHACHA20_POLY1305 only (client_suite_mismatch.json), so
# no session can ever be established.
#
# The expected outcome of this test is a FAILURE of the data plane, and the
# test passes when that failure is observed. Every assertion below is therefore
# a reverse assertion:
#
#   1. the socks5 client must fail instead of transferring data,
#   2. the client log must explain the failure with the Rust driver's warning
#      "no common cipher suite with the server" and must NOT report a completed
#      session,
#   3. both the server and the client must still be RUNNING: a peer that offers a suite the
#      server doesn't allow is rejected per session, and must not take the
#      daemons down or leave a half established session behind.
#
# With 0-RTT the client does not block waiting for a handshake response before
# returning the CONNECT stream: the first datagram already carries the
# handshake request and the SOCKS5 request (piggyback), encrypted under an early
# key derived from the static key. Reads/writes on that stream are gated until
# the forward-secret key swap completes. On NoCommonSuite the key swap fails
# and the first data-plane I/O fails (or the probe times out) — the failure is
# therefore observed on data I/O, not on handshake timing. This test deliberately
# does not assert exact timing semantics.
#
# The reason of the rejection is written to the client log at WARN level by
# rust/crates/shadowlemon-protocol/src/driver.rs. The successful-session log
# lines are at DEBUG level, so client_suite_mismatch.json sets
# "loggingLevel": "DEBUG". start_client in libtest.sh runs the client in the
# foreground and captures its log in $HOME/.cache/shadowlemon/client.log.
NO_COMMON_SUITE_LINE="no common cipher suite with the server"
HANDSHAKE_LINE="session established to"
STREAM_HANDSHAKE_LINE="UDP stream handshake completed"

# count_client_log_matches <substring>
# Prints how many lines of the client log contain the given substring.
function count_client_log_matches() {
    local pattern=$1
    local count

    # "grep | wc -l" keeps this non-fatal when the log file is missing or no
    # line matches, so that "set -e" doesn't abort with an empty diagnostic.
    count=$(grep -h -F "$pattern" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | wc -l)
    echo "$((count))"
}

# print_client_log_tail <number of lines>
function print_client_log_tail() {
    local lines=$1

    echo "========== BEGIN TAIL OF CLIENT LOG =========="
    tail -n "$lines" "$CLIENT_LOG_DIR"/*.log 2>/dev/null || true
    echo "==========  END TAIL OF CLIENT LOG  =========="
}

# wait_for_client_log_match <substring> <max number of seconds to wait>
# The failed handshake is reported by the client runtime, which may write the
# log line slightly after the socks5 client observed the failure. This waits
# for the line with a bounded number of retries, and returns 1 when the line
# never appears.
function wait_for_client_log_match() {
    local pattern=$1
    local remaining=$2

    while [[ "$remaining" -gt 0 ]]; do
        if [[ "$(count_client_log_matches "$pattern")" -gt 0 ]]; then
            return 0
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    return 1
}

# assert_daemon_running <client|server> <daemon description>
function assert_daemon_running() {
    local cmd=$1
    local desc=$2
    local status

    if ! status=$("$TEST_BINARY" "$cmd" status 2>&1); then
        status="$TEST_BINARY $cmd status failed: $status"
    fi
    echo "$desc status:"
    echo "$status"
    if [[ "$status" != *RUNNING* ]]; then
        echo "$desc is not running after the server rejected a handshake"
        echo "without a common cipher suite: the mismatch must be rejected per"
        echo "session instead of taking the daemon down."
        print_client_log_tail 80
        print_client_log
        exit 1
    fi
}

# Update server with the config that only allows AES-128-GCM.
apply_server_config server_suite_mismatch.json

# Start the server daemon.
start_server

# Update client with the config that only offers XCHACHA20-POLY1305.
apply_client_config client_suite_mismatch.json

# Start the client.
start_client

# Start testing. The socks5 connection MUST fail: no cipher suite is shared by
# the two configurations, so the forward-secret key swap never completes and
# the gated data-plane I/O fails.
#
# The probe retries a connection that failed, so a permanent misconfiguration
# makes it run until "timeout" kills it. Either a non-zero exit or a timeout
# is an expected outcome here; the assertions below prove the failure was a
# cipher suite mismatch rather than a working connection or a crashed daemon.
sleep 2
echo ">>> socks5 - new connections - no common cipher suite, failure is expected <<<"
probe_exit_code=0
timeout 20 ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
    -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
    -test_case=new_conn -num_request=1 \
    || probe_exit_code=$?

if [[ "$probe_exit_code" -eq 0 ]]; then
    echo "the socks5 client transferred data although the server allows only"
    echo "CIPHER_SUITE_AES_128_GCM and the client offers only CIPHER_SUITE_XCHACHA20_POLY1305."
    echo "help: check that server_suite_mismatch.json sets cipherSuites to CIPHER_SUITE_AES_128_GCM"
    echo "help: and that client_suite_mismatch.json sets profiles[0].cipherSuites to CIPHER_SUITE_XCHACHA20_POLY1305."
    print_client_log_tail 80
    print_client_log
    exit 1
fi

echo "the socks5 client never transferred data (exit code $probe_exit_code), as expected."

# The failed handshake must be explained in the client log.
if ! wait_for_client_log_match "$NO_COMMON_SUITE_LINE" 10; then
    echo "the client log does not explain why the handshake failed."
    echo "the expected log line is written by rust/crates/shadowlemon-protocol/src/driver.rs:"
    echo "  warn!(\"no common cipher suite with the server\")"
    echo "help: check that client_suite_mismatch.json sets \"loggingLevel\": \"DEBUG\","
    echo "help: and that the server allows CIPHER_SUITE_AES_128_GCM while the client offers"
    echo "help: CIPHER_SUITE_XCHACHA20_POLY1305, so discovery succeeds but negotiation doesn't."
    print_client_log_tail 80
    print_client_log
    exit 1
fi

no_common_suite_count=$(count_client_log_matches "$NO_COMMON_SUITE_LINE")
echo "the client log reports the cipher suite mismatch $no_common_suite_count time(s):"
grep -h -F "$NO_COMMON_SUITE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true

# No session may have been established. Check both the UDP-associate
# establishment line and the CONNECT stream key-swap completion line; the
# latter is where a CONNECT session's suite negotiation becomes observable
# under 0-RTT.
handshake_count=$(count_client_log_matches "$HANDSHAKE_LINE")
stream_count=$(count_client_log_matches "$STREAM_HANDSHAKE_LINE")
if [[ "$handshake_count" -ne 0 || "$stream_count" -ne 0 ]]; then
    echo "cipher suite assertion FAILED: $handshake_count session(s) and $stream_count stream(s)"
    echo "completed their handshake although the server and the client don't share a cipher suite:"
    grep -h -F "$HANDSHAKE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
    grep -h -F "$STREAM_HANDSHAKE_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
    print_client_log_tail 80
    print_client_log
    exit 1
fi
echo "cipher suite assertion passed: no session or stream completed its handshake."

# The rejected handshake must not affect the daemons.
assert_daemon_running server "server"
assert_daemon_running client "client"

print_client_log_tail 20

# Stop the client.
stop_client

# Stop the server daemon.
stop_server

delete_client_log

echo "Cipher suite mismatch test is successful: the handshake was rejected and the daemons survived."
