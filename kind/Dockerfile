FROM kindest/node:v1.24.6-kubewharf.7
RUN sed -i -e "s|registry.k8s.io/pause:3.7|kubewharf/pause:3.7|g" /etc/containerd/config.toml
COPY config.toml /etc/containerd/
