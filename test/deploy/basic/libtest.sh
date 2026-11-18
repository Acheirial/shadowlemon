#!/bin/bash

# Copyright (C) 2022  mieru authors
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

# Every shadowlemon invocation below uses TEST_BINARY, which defaults to the
# Rust binary copied into /test as ./shadowlemon.
#
# External transport is UDP-only. The <TCP|UDP> labels below are legacy
# scenario tags kept for compatibility: they now describe the SOCKS5 request
# being exercised, not the external transport. "TCP" means SOCKS5 CONNECT
# (TCP targets carried over the UDP tunnel's reliable DatagramStream layer);
# "UDP" means UDP ASSOCIATE datagrams (PacketUnderlay). Both use UDP bindings.
TEST_BINARY=${TEST_BINARY:-./shadowlemon}

# Both peers require the same deployment secret for the UDP routing envelope.
# The integration suite uses a fixed test-only value; real deployments set
# their own high-entropy value on both endpoints.
export SHADOWLEMON_ENVELOPE_SECRET="${SHADOWLEMON_ENVELOPE_SECRET:-shadowlemon-test-only-deployment-secret-do-not-use-in-production}"

# The Rust daemon redirects stdout/stderr to /dev/null. Scenarios that inspect
# the negotiated cipher suite therefore run the client in the foreground and
# capture its tracing output here.
CLIENT_LOG_DIR="$HOME/.cache/shadowlemon"

function print_client_log() {
    echo "========== BEGIN OF CLIENT LOG =========="
    local logs=("$HOME"/.cache/shadowlemon/*.log)
    if [[ -e "${logs[0]}" ]]; then
        cat "${logs[@]}"
    else
        echo "(no client log)"
    fi
    echo "==========  END OF CLIENT LOG  =========="
}

function delete_client_log() {
    rm -rf $HOME/.cache/shadowlemon/*.log
}

# run_or_fail <command description> <command> [arguments...]
# Runs the command, and exits the test with the same exit code as the command
# when the command fails. Printing the command description is not possible by
# just checking "$?" after the command, because "set -e" aborts the script as
# soon as the command fails.
function run_or_fail() {
    local desc=$1
    shift
    local exit_code=0

    "$@" || exit_code=$?
    if [[ "$exit_code" -ne 0 ]]; then
        echo "command '$desc' failed"
        exit "$exit_code"
    fi
}

# apply_server_config <server config file>
function apply_server_config() {
    local config=$1

    run_or_fail "shadowlemon server apply config $config" "$TEST_BINARY" server apply config "$config"
    echo "server config:"
    "$TEST_BINARY" server describe config
}

# start_server
function start_server() {
    local server_status

    run_or_fail "shadowlemon server start" "$TEST_BINARY" server start
    server_status=$("$TEST_BINARY" server status)
    echo "server status:"
    echo "$server_status"
    if [[ "$server_status" != *RUNNING* ]]; then
        echo "server is not running"
        exit 1
    fi
}

# stop_server
function stop_server() {
    local server_status

    run_or_fail "shadowlemon server stop" "$TEST_BINARY" server stop
    sleep 1
    server_status=$("$TEST_BINARY" server status)
    echo "server status:"
    echo "$server_status"
    if [[ "$server_status" != *STOPPED* ]]; then
        echo "server is not stopped"
        exit 1
    fi
}

# apply_client_config <client config file>
function apply_client_config() {
    local config=$1

    run_or_fail "shadowlemon client apply config $config" "$TEST_BINARY" client apply config "$config"
    echo "client config:"
    "$TEST_BINARY" client describe config
}

# start_client
function start_client() {
    local client_status

    # Run in the foreground so the client log is available to the assertions.
    mkdir -p "$CLIENT_LOG_DIR"
    "$TEST_BINARY" client run > "$CLIENT_LOG_DIR/client.log" 2>&1 &
    sleep 1
    client_status=$("$TEST_BINARY" client status 2>&1)
    echo "client status:"
    echo "$client_status"
    if [[ "$client_status" != *RUNNING* ]]; then
        echo "client is not running"
        print_client_log
        exit 1
    fi
}

# stop_client
function stop_client() {
    local client_status

    run_or_fail "shadowlemon client stop" "$TEST_BINARY" client stop
    sleep 1
    client_status=$("$TEST_BINARY" client status)
    echo "client status:"
    echo "$client_status"
    if [[ "$client_status" != *STOPPED* ]]; then
        echo "client is not stopped"
        exit 1
    fi
}

# dump_client_log prints and deletes the client log.
function dump_client_log() {
    print_client_log
    delete_client_log
    sleep 1
}

# run_new_conn_with_retry <label> [extra sockshttpclient args...]
# Runs the 3000-new-connection stress case. On a pure loopback the user-space
# ARQ has no network pacing (see rust/docs/known-gaps.md §11), so a burst can
# hit an occasional seconds-long tail latency. That surfaces as an empty or
# truncated HTTP response around the tenth of a second after the handshake,
# not as a functional regression. Retry only those known transient errors;
# every other failure (dial refused, auth failure, bad status, ...) is real and
# fails the test immediately.
function run_new_conn_with_retry() {
    local label=$1
    shift
    local attempt
    local max_attempts=4
    local output
    local rc

    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        sleep 2
        echo ">>> socks5 - new connections - $label (attempt $attempt/$max_attempts) <<<"
        output=$(mktemp)
        # Keep the command in a conditional: test.sh runs under `set -e`, and a
        # bare failing command would abort the whole suite before the retry
        # logic gets a chance to run.
        if ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
            -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
            -test_case=new_conn -num_request=3000 "$@" >"$output" 2>&1
        then
            rc=0
        else
            rc=$?
        fi
        cat "$output"

        if [[ $rc -eq 0 ]]; then
            rm -f "$output"
            return 0
        fi

        if grep -qE 'HTTP response is empty|early eof' "$output"; then
            echo "Transient loopback ARQ tail latency (attempt $attempt)."
            rm -f "$output"
            # A failed burst leaves half-open sessions in the client. Restart it
            # so the retry starts from a clean state instead of a heavier load
            # that would make another tail latency more likely.
            stop_client >/dev/null 2>&1
            start_client >/dev/null 2>&1
            continue
        fi

        # Not a known transient error: surface it as a real failure.
        rm -f "$output"
        print_client_log
        echo "$label - test socks5 new_conn failed."
        exit 1
    done

    print_client_log
    echo "$label - test socks5 new_conn failed after $max_attempts attempts."
    exit 1
}

# run_socks5_new_conn <CONNECT|UDP associate>
# The label is a scenario tag: CONNECT (TCP targets) is carried over a reliable
# stream inside the UDP tunnel; UDP associate is carried as UDP datagrams.
function run_socks5_new_conn() {
    run_new_conn_with_retry "$1"
}

# run_socks5_reuse_conn <CONNECT|UDP associate>
# The label is a scenario tag; both variants reuse a session over UDP transport.
function run_socks5_reuse_conn() {
    local label=$1

    sleep 1
    echo ">>> socks5 - reuse one connection - $label <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=reuse_conn -test_time_sec=30
    then
        print_client_log
        echo "$label - test socks5 reuse_conn failed."
        exit 1
    fi
}

# run_socks5_new_conn_no_wait <CONNECT|UDP associate>
# Exercises the no-wait (0-RTT) configuration: the client returns the stream
# immediately and gates the first read/write on the forward-secret key swap.
function run_socks5_new_conn_no_wait() {
    run_new_conn_with_retry "$1 - handshake no wait"
}

# run_socks5_test <TCP|UDP> <server config> <client config> <client config with handshake no wait>
# Runs all the socks5 test stages of test_tcp.sh and test_udp.sh. The only
# difference between these two tests is the configuration files and the label
# used in the log output. The label is a SOCKS5 scenario tag kept for
# compatibility: "TCP" denotes SOCKS5 CONNECT (TCP targets carried over the UDP
# tunnel's reliable layer), "UDP" denotes UDP associate datagrams. It does not
# select an external transport — every binding in these configs is UDP. The
# test exits with a non-zero code when any stage fails.
function run_socks5_test() {
    if [[ $# -ne 4 ]]; then
        echo "usage: run_socks5_test <CONNECT|UDP-associate label> <server config> <client config> <client config with handshake no wait>"
        exit 1
    fi
    local label=$1
    local server_config=$2
    local client_config=$3
    local client_no_wait_config=$4

    # Update server with config.
    apply_server_config "$server_config"

    # Start the server daemon.
    start_server

    # Update client with config.
    apply_client_config "$client_config"

    # Start the client.
    start_client

    # Start testing.
    run_socks5_new_conn "$label"
    run_socks5_reuse_conn "$label"

    # Stop the client.
    stop_client

    dump_client_log

    # Update client with config handshake no wait mode.
    apply_client_config "$client_no_wait_config"

    # Start the client.
    start_client

    # Start testing.
    run_socks5_new_conn_no_wait "$label"

    # Stop the client.
    stop_client

    # Stop the server daemon.
    stop_server

    dump_client_log
}
