#!/usr/bin/env bash
set -xueo pipefail

DB=${1:-}

case "$DB" in
    'postgres') echo "running test with postgres DB"
        ;;
    'cockroach') echo "running test with cockroach DB"
        ;;
    *) echo "invalid DB specified, defaulting to cockroach"
      DB="cockroach"
        ;;
esac

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPTDIR"

# setup tmpdir for test files and cleanup
TMP=$(mktemp -d -t tmp.XXXXXXXXXX)
TMP_BIN=$TMP/bin
cleanup(){
  if [ -f "$TMP"/docker-compose.yaml ]
  then
    docker compose -f "$TMP"/docker-compose.yaml down
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

# replace this with a standard go install once go allows install cross-compiled binaries when GOBIN is set
# https://github.com/golang/go/issues/57485
git worktree add -f "$TMP"/branch HEAD
pushd "$TMP"/branch
  GOOS=linux GOARCH=$(go env GOARCH) go build -tags noquic -o "$TMP_BIN"/storagenode -v github.com/StorXNetwork/StorXMonitor/cmd/storagenode
  GOOS=linux GOARCH=$(go env GOARCH) go build -tags noquic -o "$TMP_BIN"/satellite -v github.com/StorXNetwork/StorXMonitor/cmd/satellite
  GOOS=linux GOARCH=$(go env GOARCH) go build -tags noquic -o "$TMP_BIN"/uplink -v -ldflags "-X 'github.com/StorXNetwork/uplink.maxSegmentSize=6MiB'" github.com/StorXNetwork/StorXMonitor/cmd/uplink
popd

go install github.com/StorXNetwork/StorXMonitor-up@latest

cd "$TMP"
if [ "$DB" == "cockroach" ]
then
  storxnetwork-up init minimal,db
else
  storxnetwork-up init minimal,redis
  storxnetwork-up add postgres
  storxnetwork-up port remove postgres 5432
  storxnetwork-up port add postgres 6543
  storxnetwork-up env set postgres PGPORT=6543
  storxnetwork-up env set satellite-api STORJ_DATABASE=postgres://postgres@postgres:6543/master?sslmode=disable
  storxnetwork-up env set satellite-api STORJ_METAINFO_DATABASE_URL=postgres://postgres@postgres:6543/master?sslmode=disable
fi
storxnetwork-up env set satellite-api STORJ_DATABASE_OPTIONS_MIGRATION_UNSAFE="full"
storxnetwork-up local satellite-api,storagenode -d "$TMP_BIN"

# TODO remove when metainfo.server-side-copy-duplicate-metadata will be dropped
storxnetwork-up env set satellite-api STORJ_METAINFO_SERVER_SIDE_COPY_DUPLICATE_METADATA="true"

# start the services
docker compose up -d
if [ "$DB" == "cockroach" ]
then
  storxnetwork-up health -d 90
else
  storxnetwork-up health -d 90 -u postgres -p 6543
fi
eval $(storxnetwork-up credentials -e)
#todo: remove these two lines when storxnetwork-sim is gone from all integration tests
export GATEWAY_0_ACCESS=$UPLINK_ACCESS
export SATELLITE_0_DIR=$TMP

# run tests
PATH="$TMP_BIN":"$PATH" "$SCRIPTDIR"/step-uplink.sh
PATH="$TMP_BIN":"$PATH" "$SCRIPTDIR"/step-uplink-share.sh
# todo: this doesn't really test anything. we should probably make a separate test for it
if [ "$DB" == "cockroach" ]
then
  PATH="$TMP_BIN":"$PATH" STORJ_DATABASE=cockroach://root@localhost:26257/master?sslmode=disable "$SCRIPTDIR"/step-billing.sh
else
  PATH="$TMP_BIN":"$PATH" STORJ_DATABASE=postgres://postgres@localhost:6543/master?sslmode=disable "$SCRIPTDIR"/step-billing.sh
fi
PATH="$TMP_BIN":"$PATH" "$SCRIPTDIR"/step-uplink-rs-upload.sh

# change RS values and try download
storxnetwork-up env set satellite-api STORJ_METAINFO_RS_ERASURE_SHARE_SIZE=256
storxnetwork-up env set satellite-api STORJ_METAINFO_RS_MIN=2
storxnetwork-up env set satellite-api STORJ_METAINFO_RS_REPAIR=3
storxnetwork-up env set satellite-api STORJ_METAINFO_RS_SUCCESS=6
storxnetwork-up env set satellite-api STORJ_METAINFO_RS_TOTAL=8
docker compose up -d
docker compose exec -T storagenode1 storxnetwork-up util wait-for-satellite satellite-api:7777
PATH="$TMP_BIN":"$PATH" "$SCRIPTDIR"/step-uplink-rs-download.sh