ARG DOCKER_ARCH

# Satellite UI static asset generation
FROM node:18.17.0 as ui
WORKDIR /app
COPY storagenodeweb /app
# Need to clean up (or ignore) local folders like node_modules, etc...
RUN npm install
RUN npm run build


# Install storagenode helper (for local/dev runs)
FROM --platform=amd64 golang:latest AS storx-node-setup
WORKDIR /app
COPY . .
COPY --from=ui /app/dist /app/storagenodeweb/dist
RUN go build -o /go/bin/storagenode ./cmd/storagenode


FROM amd64/debian:bookworm-slim

ENV GOARCH amd64
ENV PATH=$PATH:/app
WORKDIR /app

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates supervisor unzip wget
RUN update-ca-certificates

COPY --from=ui /app/static /web/static
COPY --from=ui /app/dist /web/dist
COPY --from=storx-node-setup /go/bin/storagenode /app/storagenode
RUN chmod +x /app/storagenode

RUN mkdir -p /var/log/supervisor /app
COPY docker/entrypoint /
RUN mkdir -p /etc/supervisor
COPY docker/etc/supervisor/supervisord.conf /etc/supervisor
COPY docker/bin/stop-supervisor /bin
COPY docker/bin/systemctl /bin
COPY docker/app/dashboard.sh /app

# set permissions to allow non-root access
RUN chmod -R a+rw /etc/supervisor /var/log/supervisor /app
# remove the default supervisord.conf
RUN rm -rf /etc/supervisord.conf
# create a symlink to custom supervisord config file at the default location
RUN ln -s /etc/supervisor/supervisord.conf /etc/supervisord.conf

EXPOSE 28967
EXPOSE 14002

WORKDIR /app
ENTRYPOINT ["/entrypoint"]

ENV ADDRESS="" \
    EMAIL="" \
    WALLET="" \
    STORAGE="2.0TB" \
    SETUP="false" \
    LOG_LEVEL=""
