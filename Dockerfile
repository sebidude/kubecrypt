FROM golang:1.13-alpine as builder

RUN apk add --no-cache --update git make
RUN mkdir /build
WORKDIR /build
RUN git clone https://github.com/sebidude/kubecrypt.git
WORKDIR /build/kubecrypt
RUN make unittest build-linux test

FROM scratch

COPY --from=builder /build/kubecrypt/build/linux/kubecrypt /usr/bin/kubecrypt
ENTRYPOINT ["/usr/bin/kubecrypt"]
