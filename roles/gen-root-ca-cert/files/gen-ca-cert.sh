#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Export proxy to ensure commands like curl could work
[[ -n "${HTTP_PROXY:-}" ]]  && export HTTP_PROXY=${HTTP_PROXY}
[[ -n "${HTTPS_PROXY:-}" ]] && export HTTPS_PROXY=${HTTPS_PROXY}

# ----------------------------------------------------------------
# Caller should set in the ev:
# NODE_IPS - IPs of all cluster servers
# NODE_DNS - DNS names of all cluster servers
# ARCH - what arch of cfssl should be downloaded

# Also the following will be respected
# CERT_DIR - where to place the finished certs (we create tmp cert config directory user CERT_DIR)
# CERT_GROUP - who the group owner of the cert files should be
# USE_LOCAL_BIN - '1' when using local cfssl, cfssljson binary at config directory

#node_ips="${NODE_IPS:="${1}"}"
#node_dns="${NODE_DNS:=""}"
arch="${ARCH:-"linux-amd64"}"
cert_dir="${CERT_DIR:-"/etc/cert-cache/ca"}"
cert_group="${CERT_GROUP:="root"}"
#use_local="${USE_LOCAL_BIN:="${1}"}"

# The following certificate pairs are created:
#
#  - ca (the cluster's certificate authority)
#  - (not yet use for master ca gen) server (for etcd access)
#  - (not yet use for  master ca gen) client (for kube-apiserver, etcdctl)
#  - (not yes use for master ca gen) peer (for etcd peer to peer communication)

# add cfssl utility bin directory to path (/usr/local/bin)
export PATH="$PATH:/usr/local/bin"

# enter directory to create root ca cert 
cd "${cert_dir}"

# debug trace
#mkdir -p "${cert_dir}"
#pwd > "${cert_dir}/trace.log"
#echo $PATH >> "${cert_dir}/trace.log"
#ls -al ./* >> "${cert_dir}/trace.log"
#which cfssl >> "${cert_dir}/trace.log"
#which cfssljson >> "${cert_dir}/trace.log"
#cfssl gencert -initca ca-csr.json | cfssljson -bare ca > "${cert_dir}/trace-cfssl.log"

# exec - generate root-CA ca cert using cfssl/cfssljson utility
# generate the master CA/CERT(ca.pem, ca-key.pem) using ca-config.json, ca-csr.json 
if ! (cfssl gencert -initca ca-csr.json | cfssljson -bare ca -) >/dev/null 2>&1; then
    echo "=== Failed to generate CA certificates: Aborting ===" 1>&2
    exit 2
fi

### 
# exec - generate intermediate-CA
# generate the intermediate-CA, using intermediate-ca csr
# files will generate:
# 1. intermediate-ca.csr
# 2. intermediate-ca.pem
# 3. intermediate-ca-key.pem
#
if ! (cfssl gencert -initca intermediate-ca-csr.json | cfssljson -bare intermediate-ca -) >/dev/null 2>&1; then
    echo "=== Failed to generate intermediate-CA certificates: Aborting ===" 1>&2
    exit 2
fi

# exec - sign intermediate-CA with root-CA, using intermediate-ca.csr and using root-to-intermediate-ca-config.json as ca-config
# generate signed intermediate-CA file - intermediate-ca.pem
#
if ! (cfssl sign -ca ca.pem -ca-key ca-key.pem -config root-to-intermediate-ca-config.json -profile kubernetes intermediate-ca.csr | cfssljson -bare intermediate-ca -) >/dev/null 2>&1; then
    echo "=== Failed to generate root-CA certified intermediate-CA certificate: Aborting ===" 1>&2
    exit 2
fi

# copy and use intermediate-CA as front-proxy client CA
cp intermediate-ca.pem front-proxy-client-ca.pem
cp intermediate-ca-key.pem front-proxy-client-ca-key.pem
cp intermediate-ca.csr front-proxy-client-ca.csr

# debug
#ls -al ./* > "${cert_dir}/files.tx"
