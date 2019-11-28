FROM scratch

COPY build/linux/kubecrypt /usr/bin/kubecrypt
ENTRYPOINT ["/usr/bin/kubecrypt"]
