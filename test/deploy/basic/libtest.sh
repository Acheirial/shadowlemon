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
TEST_BINARY=${TEST_BINARY:-./shadowlemon}

# The Rust daemon redirects stdout/stderr to /dev/null. Scenarios that inspect
# the negotiated cipher suite therefore run the client in the foreground and
# capture its tracing output here.
CLIENT_LOG_DIR="$HOME/.cache/shadowlemon"

function print_client_log() {
    echo "========== BEGIN OF CLIENT LOG =========="
    cat $HOME/.cache/shadowlemon/*.log
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

# run_socks5_new_conn <TCP|UDP>
function run_socks5_new_conn() {
    local label=$1

    sleep 2
    echo ">>> socks5 - new connections - $label <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=new_conn -num_request=3000
    then
        print_client_log
        echo "$label - test socks5 new_conn failed."
        exit 1
    fi
}

# run_socks5_reuse_conn <TCP|UDP>
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

# run_socks5_new_conn_no_wait <TCP|UDP>
function run_socks5_new_conn_no_wait() {
    local label=$1

    sleep 2
    echo ">>> socks5 - new connections - $label - handshake no wait <<<"
    if ! ./sockshttpclient -dst_host=127.0.0.1 -dst_port=8080 \
        -local_proxy_host=127.0.0.1 -local_proxy_port=1080 \
        -test_case=new_conn -num_request=3000
    then
        print_client_log
        echo "$label - test socks5 new_conn (handshake no wait) failed."
        exit 1
    fi
}

# run_socks5_test <TCP|UDP> <server config> <client config> <client config with handshake no wait>
# Runs all the socks5 test stages of test_tcp.sh and test_udp.sh. The only
# difference between these two tests is the configuration files, and the label
# used in the log output. The test exits with a non-zero code when any stage
# fails.
function run_socks5_test() {
    if [[ $# -ne 4 ]]; then
        echo "usage: run_socks5_test <TCP|UDP> <server config> <client config> <client config with handshake no wait>"
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
