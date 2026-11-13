# Minimal local replica of the challenge service.
# Native Ubuntu 20.04 glibc 2.31, no nsjail/PoW (those need the kctf image and privileges).
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat patchelf \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 user
WORKDIR /home/user

# dist/rusty_ptrs is patched for the local debug setup; restore stock
# interpreter and paths so the container uses its own glibc 2.31.
COPY dist/rusty_ptrs ./rusty_ptrs
COPY flag.txt ./flag.txt
RUN patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 --remove-rpath rusty_ptrs \
 && chmod 555 rusty_ptrs \
 && chmod 444 flag.txt

USER user
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./rusty_ptrs"]
