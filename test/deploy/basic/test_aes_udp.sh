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

# Test the AES-256-GCM cipher suite over the UDP-only transport, with the socks5
# UDP associate data plane of test_mix_udp_associate.sh.
#
# External transport is UDP-only: every port binding in server_aes_udp.json and
# client_aes_udp.json is a UDP binding. server_aes_udp.json only allows
# CIPHER_SUITE_AES_256_GCM. client_aes_udp.json offers CIPHER_SUITE_AES_256_GCM
# and the CIPHER_SUITE_XCHACHA20_POLY1305 fallback. Every session of this test
# therefore runs as a UDP-associate datagram session (a PacketUnderlay), so a
# successful run proves the AES-256-GCM suite end to end over UDP.
#
# The negotiated suite is observable in the client log: the Rust driver logs at
# DEBUG level "UDP session established to PacketUnderlay{" with a `suite=<name>`
# field on the same line (rust/crates/shadowlemon-protocol/src/driver.rs). For
# SOCKS5 CONNECT the driver instead logs "UDP stream session opened to
# StreamUnderlay{" (no suite field) plus "UDP stream handshake completed" with
# the suite once the forward-secret key swap finishes. This scenario only uses
# UDP associate, so the PacketUnderlay line is the relevant one.
# client_aes_udp.json therefore sets "loggingLevel": "DEBUG"; with the "INFO"
# level used by client_udp.json the line is never emitted. start_client in
# libtest.sh runs the client in the foreground and captures its log in
# $HOME/.cache/shadowlemon/client.log.
#
# NOTE: only the client logs the negotiated suite. The server logs the reasons
# of a rejection, but nothing when a handshake succeeds.
AES_SUITE="AES_256_GCM"
PACKET_UNDERLAY_LINE="to PacketUnderlay{"
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

# count_aes_sessions <underlay marker>
# Number of established sessions on the given transport whose log line also
# carries the AES_256_GCM suite field.
function count_aes_sessions() {
    local marker=$1
    local count

    count=$(grep -h -F "$marker" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | grep -F -c "$AES_SUITE" || true)
    echo "$((count))"
}

# print_client_log_tail <number of lines>
function print_client_log_tail() {
    local lines=$1

    echo "========== BEGIN TAIL OF CLIENT LOG =========="
    tail -n "$lines" "$CLIENT_LOG_DIR"/*.log 2>/dev/null || true
    echo "==========  END TAIL OF CLIENT LOG  =========="
}

# assert_aes_cipher_suite_over_udp
# Fails the test unless at least one established session logged that it used
# AES-256-GCM, and unless at least one session was attached to a UDP datagram
# underlay. An "apparently working" data plane is NOT enough: a silent fallback
# to CIPHER_SUITE_XCHACHA20_POLY1305 would still carry traffic. The external
# transport is UDP-only, so StreamUnderlay (the CONNECT reliable layer) is only
# reported as a sanity check and is never expected in this UDP-associate test.
function assert_aes_cipher_suite_over_udp() {
    local session_count
    local aes_packet_count
    local aes_stream_count

    session_count=$(count_client_log_matches "$SESSION_ESTABLISHED_LINE")
    aes_packet_count=$(count_aes_sessions "$PACKET_UNDERLAY_LINE")
    aes_stream_count=$(count_aes_sessions "$STREAM_UNDERLAY_LINE")

    echo "session assertion: $session_count session(s) were established."
    echo "transport assertion: $aes_packet_count AES session(s) used the UDP datagram layer (PacketUnderlay) and"
    echo "transport assertion: $aes_stream_count AES session(s) used the CONNECT stream layer (StreamUnderlay)."

    if [[ "$session_count" -eq 0 ]]; then
        echo "session assertion FAILED: no client log line reports an established session at all,"
        echo "so the session either wasn't established or the client didn't log at DEBUG level."
        echo "the expected log lines are written by rust/crates/shadowlemon-protocol/src/driver.rs:"
        echo "  UDP session established to PacketUnderlay{ ... suite=<name> ..."
        print_client_log_tail 80
        print_client_log
        exit 1
    fi

    if [[ "$aes_packet_count" -eq 0 ]]; then
        echo "cipher suite assertion FAILED: none of the $session_count established session(s) used"
        echo "AES_256_GCM over the UDP transport."
        echo "observed established sessions:"
        grep -h -F "$SESSION_ESTABLISHED_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | head -n 3 || true
        echo "a XCHACHA20_POLY1305 suite above means the client fell back to the fallback suite"
        echo "instead of using the AES-256-GCM suite both configurations ask for."
        echo "help: check that server_aes_udp.json sets cipherSuites to CIPHER_SUITE_AES_256_GCM,"
        echo "help: that client_aes_udp.json sets profiles[0].cipherSuites and \"loggingLevel\": \"DEBUG\","
        echo "help: and that the log doesn't contain 'no common cipher suite with the server'."
        print_client_log_tail 80
        print_client_log
        exit 1
    fi

    echo "cipher suite assertion passed: $aes_packet_count AES session(s) used the UDP datagram layer."
    if [[ "$aes_stream_count" -gt 0 ]]; then
        echo "note: $aes_stream_count AES session(s) also used the CONNECT-over-UDP stream layer."
    fi
    grep -h -F "$PACKET_UNDERLAY_LINE" "$CLIENT_LOG_DIR"/*.log 2>/dev/null | grep -F "$AES_SUITE" | head -n 3 || true
}

# Update server with the mixed config that only allows AES-256-GCM.
apply_server_config server_aes_udp.json

# Start the server daemon.
start_server

# Update client with the UDP config that offers AES-256-GCM.
apply_client_config client_aes_udp.json

# Start the client.
start_client

# Start testing.
sleep 2
echo ">>> socks5 UDP associate - AES-256-GCM over UDP <<<"
if ! ./socksudpclient -dst_host=127.0.0.1 -dst_port=9090 \
    -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
    -interval_ms=10 -num_request=100 -num_conn=60
then
    print_client_log
    echo "Test AES over UDP failed: the socks5 UDP associate data plane didn't carry the UDP packets."
    exit 1
fi

# The sessions used by the stage above must have negotiated AES-256-GCM over
# the UDP transport.
assert_aes_cipher_suite_over_udp

# The full client log is not dumped on success: with DEBUG level it is large,
# and the matching lines printed by the assertion are the evidence that the
# negotiated cipher suite and the transport were the expected ones.
print_client_log_tail 20

# Stop the client.
stop_client

# Stop the server daemon.
stop_server

delete_client_log

echo "AES over UDP test is successful."
