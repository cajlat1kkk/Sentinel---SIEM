ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
ARG DEBIAN_MIRROR=
RUN if [ -n "$DEBIAN_MIRROR" ] && [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i "s|http://deb.debian.org/debian|${DEBIAN_MIRROR%/}|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
       -o APT::Update::Error-Mode=any update \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
       install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config qt6-base-dev qt6-svg-dev \
    libqt6sql6-psql libqt6sql6-sqlite libdpdk-dev dpkg-dev nftables python3 \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 \
       -o APT::Update::Error-Mode=any update \
    && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    && cmake --build build -j 4 \
    && QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure \
    && python3 scripts/test-dpdk.py \
    && pcap_package=$(dpkg-query -W -f='${Package}' 'librte-net-pcap*') \
    && test -n "$pcap_package" \
    && cd build && cpack -G DEB \
       -D "CPACK_DEBIAN_PACKAGE_DEPENDS=libqt6sql6-psql, libqt6sql6-sqlite, libqt6svg6, $pcap_package"
CMD ["/work/build/sentinel-siem", "--demo", "--smoke-test"]
