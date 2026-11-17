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

# Test socks5 proxy with a configuration that forces the AES-256-GCM cipher
# suite. server_aes.json only allows CIPHER_SUITE_AES_256_GCM, and
# client_aes.json prefers it and falls back to CIPHER_SUITE_XCHACHA20_POLY1305,
# so a successful session must have negotiated AES-256-GCM.
#
# The negotiation result is observable in the client log: when a session is
# attached to the TCP transport the Rust driver logs, at DEBUG level,
# "TCP session established to StreamUnderlay{" with a `suite=<name>` field on
# the same line (rust/crates/shadowlemon-protocol/src/driver.rs).
# client_aes.json therefore sets "loggingLevel": "DEBUG"; with the "INFO" level
# used by client_tcp.json the line is never emitted. start_client in libtest.sh
# runs the client in the foreground and captures its log in
# $HOME/.cache/shadowlemon/client.log.
#
# NOTE: only the client logs the negotiated suite. The server logs the reasons
# of a rejection, but nothing when a handshake succeeds. server_aes.json is set
# to DEBUG as well so that a rejection is visible in the container output.
AES_SUITE="AES_256_GCM"
STREAM_UNDERLAY_LINE="to StreamUnderlay{"
SESSION_ESTABLISHED_LINE="session established to"

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

# count_aes_stream_sessions
# Number of established TCP sessions whose log line also carries the
# AES_256_GCM suite field.
function count_aes_stream_sessions() {
    local count

    count=$(grep -h -F "$STREAM_UNDERLAY_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | grep -F -c "$AES_SUITE" || true)
    echo "$((count))"
}

# print_client_log_tail <number of lines>
function print_client_log_tail() {
    local lines=$1

    echo "========== BEGIN TAIL OF CLIENT LOG =========="
    tail -n "$lines" "$CLIENT_LOG_DIR"/*.log 2>/dev/null || true
    echo "==========  END TAIL OF CLIENT LOG  =========="
}

# assert_aes_cipher_suite_negotiated
# Fails the test unless at least one established session logged that it used
# AES-256-GCM. An "apparently working" data plane is NOT enough: a silent
# fallback to CIPHER_SUITE_XCHACHA20_POLY1305 would still carry traffic, and
# this assertion is what tells the two cases apart.
function assert_aes_cipher_suite_negotiated() {
    local aes_count
    local session_count

    aes_count=$(count_aes_stream_sessions)
    session_count=$(count_client_log_matches "$SESSION_ESTABLISHED_LINE")

    if [[ "$aes_count" -gt 0 ]]; then
        echo "cipher suite assertion passed: $aes_count session(s) negotiated AES_256_GCM."
        grep -h -F "$STREAM_UNDERLAY_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | grep -F "$AES_SUITE" | head -n 3 || true
        return 0
    fi

    echo "cipher suite assertion FAILED: none of the $session_count established session(s) used AES_256_GCM."
    if [[ "$session_count" -gt 0 ]]; then
        echo "the sessions were established with a different cipher suite:"
        grep -h -F "$SESSION_ESTABLISHED_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
        echo "a XCHACHA20_POLY1305 suite above means the client fell back to the default suite"
        echo "instead of using the AES-256-GCM suite both configurations ask for."
    else
        echo "no client log line reports an established session at all, so the session either"
        echo "wasn't established or the client didn't log at DEBUG level."
    fi
    echo "the expected log line is written by rust/crates/shadowlemon-protocol/src/driver.rs:"
    echo "  TCP session established to StreamUnderlay{ ... suite=AES_256_GCM ..."
    echo "help: check that server_aes.json sets cipherSuites to CIPHER_SUITE_AES_256_GCM,"
    echo "help: that client_aes.json sets profiles[0].cipherSuites and \"loggingLevel\": \"DEBUG\","
    echo "help: that the server allows a suite the client offers, and that the log doesn't"
    echo "help: contain 'no common cipher suite with the server'."
    print_client_log_tail 80
    print_client_log
    exit 1
}

# Run the AES-256-GCM test over TCP.
apply_server_config server_aes.json
start_server
apply_client_config client_aes.json
start_client

# Data plane: run the same socks5 stages as test_tcp.sh.
run_socks5_new_conn TCP
run_socks5_reuse_conn TCP

# The sessions used by the stages above must have negotiated AES-256-GCM.
assert_aes_cipher_suite_negotiated

# The full client log is not dumped on success: with DEBUG level it is large,
# and the matching lines printed by the assertion are the evidence that the
# negotiated cipher suite was the expected one.
print_client_log_tail 20

stop_client
stop_server

delete_client_log

echo "AES test is successful."
