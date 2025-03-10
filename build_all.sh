#/bin/bash
set -x

PLATFORM_FLAG=''
if [ "$(uname -m)" == "arm64" ]; then
    echo "[+] Preparing amd64 container on ARM64 machine!!"
    PLATFORM_FLAG='--platform linux/amd64'
fi
    

# build docker container
docker build . $PLATFORM_FLAG -f docker/Dockerfile -t ebpf_test
## run container
docker run $PLATFORM_FLAG  -v $PWD/build:/app/build -v $PWD/src:/app/src -it ebpf_test
## push files to dev
#adb push build/loader /data/local/tmp
#adb push build/implant.o.bpf /data/local/tmp
#adb exec-out /data/local/tmp/loader

