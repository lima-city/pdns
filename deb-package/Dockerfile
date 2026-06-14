ARG UBUNTU_RELEASE=noble

FROM ubuntu:${UBUNTU_RELEASE} AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    ruby \
    ruby-dev \
    build-essential \
    git \
  && gem install -N fpm \
  && rm -rf /var/lib/apt/lists/*

FROM ubuntu:${UBUNTU_RELEASE} AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bison \
    build-essential \
    ca-certificates \
    curl \
    flex \
    git \
    libboost-dev \
    libboost-program-options-dev \
    libboost-serialization-dev \
    libcurl4-openssl-dev \
    liblua5.4-dev \
    liblmdb-dev \
    libssl-dev \
    libsystemd-dev \
    default-libmysqlclient-dev \
    ninja-build \
    pkg-config \
    python3 \
    python3-venv \
    python3-yaml \
    ragel \
  && python3 -m venv /opt/meson \
  && /opt/meson/bin/pip install --no-cache-dir meson==1.3.2 \
  && ln -s /opt/meson/bin/meson /usr/local/bin/meson \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN meson setup /build /src \
    --prefix=/usr \
    --buildtype=release \
    --strip \
    -Dlua=lua5.4 \
    -Dlua-records=false \
    -Dmodule-bind=disabled \
    -Dmodule-gmysql=static \
    -Dmodule-lmdb=static \
    -Dmodule-pipe=disabled \
    -Dsystemd-service=disabled \
    -Dtools=true \
    -Dtools-ixfrdist=false \
    -Dunit-tests=false \
    -Dunit-tests-backends=false \
  && ninja -C /build -j "$(nproc)" pdns-mysql2lmdb

RUN mkdir -p /build/debian \
  && printf 'Source: pdns-mysql2lmdb\n\nPackage: pdns-mysql2lmdb\nArchitecture: any\nDepends: ${shlibs:Depends}\nDescription: PowerDNS MySQL to LMDB synchronizer\n PowerDNS MySQL to LMDB synchronizer\n' > /build/debian/control \
  && cd /build \
  && dpkg-shlibdeps -O -e/build/pdns-mysql2lmdb \
    | sed -e 's/^shlibs:Depends=//' -e 's/, */\n/g' \
    > /build/fpm-depends.txt

FROM base AS pdns-mysql2lmdb

ARG PACKAGE_VERSION=0.1.0
ARG PACKAGE_ITERATION=1
ARG PACKAGE_MAINTAINER="trafficplex GmbH"

WORKDIR /pkg

RUN mkdir -p /pkg/usr/bin /pkg/lib/systemd/system /pkg/etc/default /out

COPY --from=builder /build/pdns-mysql2lmdb /pkg/usr/bin/pdns-mysql2lmdb
COPY --from=builder /build/fpm-depends.txt /tmp/fpm-depends.txt
COPY deb-package/systemd/pdns-mysql2lmdb.service /pkg/lib/systemd/system/pdns-mysql2lmdb.service
COPY deb-package/default/pdns-mysql2lmdb /pkg/etc/default/pdns-mysql2lmdb

RUN chmod 0755 /pkg/usr/bin/pdns-mysql2lmdb \
  && chmod 0644 /pkg/lib/systemd/system/pdns-mysql2lmdb.service /pkg/etc/default/pdns-mysql2lmdb

RUN set -eu; \
  set --; \
  while IFS= read -r dependency; do \
    [ -n "${dependency}" ] || continue; \
    set -- "$@" --depends "${dependency}"; \
  done < /tmp/fpm-depends.txt; \
  fpm \
    -s dir \
    -t deb \
    -n pdns-mysql2lmdb \
    -v "${PACKAGE_VERSION}" \
    --iteration "${PACKAGE_ITERATION}" \
    --architecture amd64 \
    --maintainer "${PACKAGE_MAINTAINER}" \
    --description "PowerDNS MySQL to LMDB synchronizer" \
    --url "https://www.powerdns.com/" \
    --license "GPL-2.0-only" \
    --depends systemd \
    "$@" \
    --config-files /etc/default/pdns-mysql2lmdb \
    --deb-systemd-enable \
    --deb-systemd-auto-start \
    --no-deb-systemd-restart-after-upgrade \
    --deb-systemd lib/systemd/system/pdns-mysql2lmdb.service \
    -C /pkg \
    -p "/out/pdns-mysql2lmdb_${PACKAGE_VERSION}-${PACKAGE_ITERATION}_amd64.deb" \
    usr \
    etc \
    lib

FROM scratch AS export-stage

COPY --from=pdns-mysql2lmdb /out/*.deb /
