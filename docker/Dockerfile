FROM ubuntu:latest

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
 && apt-get install -y \
    gcc-aarch64-linux-gnu   \
    llvm  \
    clang  \
    make \ 
    build-essential \ 
    git \ 
    wget \
    unzip \
    libelf1t64 \
    libelf-dev \
    zlib1g-dev \
    zlib1g \
 && rm -rf /var/lib/apt/lists/*


WORKDIR /app
ADD ./docker/main.sh main.sh
RUN chmod +x main.sh
ENTRYPOINT sh -c /app/main.sh


 
 
