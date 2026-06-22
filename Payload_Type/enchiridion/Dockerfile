FROM itsafeaturemythic/mythic_python_go:latest

RUN apt-get update && apt-get upgrade -y && apt-get install -y cmake make && apt-get clean

RUN pip3 install mythic_container

# Pre-build musl toolchain + wolfssl + zlib + libcurl once at image build time.
# At runtime each agent build skips these downloads and just compiles the ~13 agent source files.
COPY enchiridion/agent_code /tmp/prebuild_agent_code
RUN cmake -S /tmp/prebuild_agent_code -B /opt/enchiridion/ext_cache \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=/tmp/prebuild_agent_code/cmake/musl-toolchain.cmake \
      -DC2_IMPL=http \
      -DENCRYPTION_MODE=STATIC_KEY && \
    cmake --build /opt/enchiridion/ext_cache --target ext_wolfssl ext_zlib ext_curl -j$(nproc) && \
    rm -rf /tmp/prebuild_agent_code

WORKDIR /Mythic/

CMD ["python3", "main.py"]
