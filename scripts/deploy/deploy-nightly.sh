#!/usr/bin/env bash
set -ex
storxnetwork-up init nomad --name=core --ip=$IP minimal,gc
storxnetwork-up image satellite-api,storagenode,gc $IMAGE:$TAG
storxnetwork-up persist storagenode,satellite-api,gc
storxnetwork-up env set satellite-api STORJ_DATABASE_OPTIONS_MIGRATION_UNSAFE=full,testdata
nomad run storxnetwork.hcl
