# Copyright (C) 2021  mieru authors
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

# Assume this file is executed with `docker build -f` from the root dir of shadowlemon project.

FROM debian:bookworm-slim

WORKDIR /test

# Copy the prebuilt Rust binaries (produced by the Makefile test-binary target)
# together with the scenario scripts and their JSON configurations. The image
# contains no compiler and performs no build of its own.
COPY bin/shadowlemon bin/httpserver bin/sockshttpclient bin/socksudpclient bin/udpserver \
     test/deploy/basic/*.json test/deploy/basic/*.sh /test/

# The Rust server keeps its pidfile here; the scripts start several servers in
# sequence, so the directory must exist and be writable in the container.
RUN mkdir -p /var/run/shadowlemon && chmod 777 /var/run/shadowlemon

ENTRYPOINT ["/bin/bash", "test.sh"]
