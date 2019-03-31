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

# Caller should set in the ev:
# NODE_IPS - IPs of all kube master servers
# LOAD_BALANCER_IP - IP of load balancer
# APISERVER_SERVICE_CLUSTER_IP - IP of apiserver service clust ip (10.254.0.1 - first address of 10.254.0.0/16 )
# NODE_DNS - DNS names of all kube master servers
# ARCH - what arch of cfssl should be downloaded

# Also the following will be respected
# CERT_DIR - where to place the finished certs. also work as work directory to gen ca cert
# CERT_GROUP - who the group owner of the cert files should be
# MASTER_CA_CONFIG_DIR - master ca-config directory. copy master ca-config from this directory
# MASTER_CA_DIR - master ca file directory. copy master ca files from this directory
# LOAD_BALANCER_IP - load balancer ip address in front of apiserver
# APISERVER_SERVICE_CLUSTER_IP - ip/network of service cluster for apiserver


# parse environment variables for internal use

node_ips="${NODE_IPS:="${1}"}"
load_balancer_ip="${LOAD_BALANCER_IP:="${1}"}"
pod_network_start_ip="${POD_NETWORK_START_IP:="${1}"}"

apiserver_service_cluster_ip_localvar="${APISERVER_SERVICE_CLUSTER_IP:="${1}"}"
cluster_kube_dns_ip_localvar="${CLUSTER_DNS_IP:="${1}"}"

node_dns="${NODE_DNS:=""}"

arch="${ARCH:-"linux-amd64"}"

cert_group="${CERT_GROUP:="root"}"

#cert_dir="${CERT_DIR:-"/etc/cert-cache/kubernetes"}"
cert_dir="${CERT_DIR:="${1}"}"

# master_ca_config_dir="${MASTER_CA_CONFIG_DIR:-"/etc/cert-cache/ca-config"}"
master_ca_config_dir="${MASTER_CA_CONFIG_DIR:="${1}"}"

#master_ca_dir="${MASTER_CA_DIR:-"/etc/cert-cache/ca"}"
master_ca_dir="${MASTER_CA_DIR:="${1}"}"

# end env parse


# The following certificate pairs are created:
#
#  - ( ca - the cluster's certificate authority - copy from master ca -  already)
#  - apiserver (for kube apiserver)
#  - admin (for kubectl administrator account client)
#  - controller-manager (for kube controller manager service)
#  - scheduler (for kube scheduler service)
#  - proxy ( for kube proxy client )

declare -a san_array=()

IFS=',' read -ra node_ips <<< "$node_ips"
for ip in "${node_ips[@]}"; do
    san_array+=(${ip})
done
IFS=',' read -ra node_dns <<< "$node_dns"
for dns in "${node_dns[@]}"; do
    san_array+=(${dns})
done

# add cfssl utility bin directory to path (/usr/local/bin)
#   - as basic bash path do not include /usr/local/bin which cfssl utility reside in
export PATH="$PATH:/usr/local/bin"

# enter work directory to create kube ca cert
cd "${cert_dir}"


# debug log
pwd > trace.log
echo ${PATH} >> trace.log
echo ${cert_dir} >> trace.log
echo ${node_ips} >> trace.log
echo ${load_balancer_ip} >> trace.log
echo ${apiserver_service_cluster_ip_localvar} >> trace.log
echo ${cluster_kube_dns_ip_localvar} >> trace.log
echo ${node_dns} >> trace.log
echo ${arch} >> trace.log
echo ${cert_group} >> trace.log
echo ${master_ca_config_dir} >> trace.log
echo ${master_ca_dir} >> trace.log
# end log

####    Generate CA CERT    #####################################################################

# get hosts string (include ip address list and hostname list of cluster masters)

cn_name="${san_array[0]}"
san_array=("${san_array[@]}")
set -- ${san_array[*]}
for arg do shift
    set -- "$@" \",\" "$arg"
done; shift
hosts_string="\"$(printf %s "$@")\""


# debug trace log
echo ${hosts_string} >> trace.log
# end log

# 1. kube-apiserver
####    generate kube apiserver csr json file ( use kube profile of ca-config.json, server/client)
# kube user: kubernetes
# kube group: kube

cat <<EOF > kube-apiserver-csr.json
{
    "CN": "kubernetes",
    "hosts": [
        "127.0.0.1","localhost",
        "$load_balancer_ip", "lb-node",
        $hosts_string,
        "$apiserver_service_cluster_ip_localvar",
        "$cluster_kube_dns_ip_localvar", 
        "$pod_network_start_ip",

        "api",
        "kubernetes",
        "kubernetes.local",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "kube",
            "OU": "internet"
        }
    ]
}
EOF


# debug use
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kube kube-apiserver-csr.json | cfssljson -bare kube-apiserver) >/dev/null 2>&1; then
    echo "=== Failed to generate kube-apiserver server certificates: Aborting ===" 1>&2
    exit 2
fi

# 1.1 kube-apiserver-client cert
####    generate kube apiserver client csr json file ( use kube profile of ca-config.json, client)
# kube user: kube-apiserver
# kube group: kube

#    "hosts": [
#    ],

cat <<EOF > kube-apiserver-client-csr.json
{
    "CN": "kube-apiserver-client",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:masters",
            "OU": "internet"
        }
    ]
}
EOF


# debug use
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-apiserver-client-csr.json | cfssljson -bare kube-apiserver-client) >/dev/null 2>&1; then
    echo "=== Failed to generate kube-apiserver-client client certificates: Aborting ===" 1>&2
    exit 2
fi

# 2. kube-admin
####    generate kube admin csr json file (use client profile of ca-config.json, client)
# kube user: kubernetes-admin
# kube group: system:masters

#    "hosts": [
#    ],

cat <<EOF > kube-admin-csr.json
{
    "CN": "kubernetes-admin",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:masters",
            "OU": "internet"
        }
    ]
}
EOF

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-admin-csr.json | cfssljson -bare kube-admin) >/dev/null 2>&1; then
    echo "=== Failed to generate kube-admin client certificates: Aborting ===" 1>&2
    exit 2
fi



# 3. kube-controller-manager
####    generate kube controller manager csr json file (use kube profile of ca-config.json, server/client)
# kube user: system:kube-controller-manager
# kube group: system:kube-controller-manager

#    "hosts": [
#        "127.0.0.1",
#        $hosts_string
#    ],

cat <<EOF > kube-controller-manager-csr.json
{
    "CN": "system:kube-controller-manager",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:kube-controller-manager",
            "OU": "internet"
        }
    ]
}
EOF

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager) >/dev/null 2>&1; then
    echo "=== Failed to generate server certificates: Aborting ===" 1>&2
    exit 2
fi


# 4. kube-scheduler
####    generate kube scheduler csr json file (use kube profile of ca-config.json, server/client)
# kube user: system:kube-scheduler
# kube group: system:kube-scheduler

#    "hosts": [
#        "127.0.0.1",
#        $hosts_string
#    ],

cat <<EOF > kube-scheduler-csr.json
{
    "CN": "system:kube-scheduler",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:kube-scheduler",
            "OU": "internet"
        }
    ]
}
EOF


if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-scheduler-csr.json | cfssljson -bare kube-scheduler) >/dev/null 2>&1; then
    echo "=== Failed to generate server certificates: Aborting ===" 1>&2
    exit 2
fi


# 5. kube-proxy
# create kube proxy csr json file ( use kube profile of ca-config, client - hosts is null )
# kube user: system:kube-proxy
# kube group: system:kube-proxy

#    "hosts": [
#    ],

cat <<EOF > kube-proxy-csr.json
{
    "CN": "system:kube-proxy",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:kube-proxy",
            "OU": "internet"
        }
    ]
}
EOF


# debug trace log
#echo "finished gen kube-proxy csr" >> trace.log
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-proxy-csr.json | cfssljson -bare kube-proxy) >/dev/null 2>&1; then
    echo "=== Failed to generate server certificates: Aborting ===" 1>&2
    exit 2
fi

# debug trace log
#echo "finished gen kube-proxy cert" >> trace.log
# end debug

# 6. kube front proxy client cert
# create kube front proxy client csr json file 
#   ( use server profile of root-to-intermediate-ca-config.json. 
#     as wu use it for apiserver to access metrics-server as client - hosts is null )
# kube user: aggregator, system:metrics-server
# kube group: kube

#    "hosts": [
#    ],

cat <<EOF > front-proxy-client-csr.json
{
    "CN": "system:metrics-server",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "kube",
            "OU": "internet"
        }
    ]
}
EOF


# debug trace log
#echo "finished gen front-proxy-client csr" >> trace.log
# end debug

if ! (cfssl gencert -ca=front-proxy-client-ca.pem -ca-key=front-proxy-client-ca-key.pem -config=root-to-intermediate-ca-config.json -profile=server front-proxy-client-csr.json | cfssljson -bare front-proxy-client) >/dev/null 2>&1; then
    echo "=== Failed to generate server certificates: Aborting ===" 1>&2
    exit 2
fi

# debug trace log
#echo "finished gen kube-proxy cert" >> trace.log
# end debug


# 7. kube-serviceaccount
# for kube service account
# create kube sa csr json file ( csr for service account client, use client profile of ca-config, client - hosts is null )
# kube user: system:serviceaccount:kube-system:default
# kube group: system:serviceaccounts

#    "hosts": [
#    ],

cat <<EOF > kube-serviceaccount-csr.json
{
    "CN": "system:serviceaccount:kube-system:default",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:serviceaccounts",
            "OU": "internet"
        }
    ]
}
EOF


# debug trace log
#echo "finished gen kube-serviceaccount csr" >> trace.log
# end debug


if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-serviceaccount-csr.json | cfssljson -bare kube-serviceaccount) >/dev/null 2>&1; then
    echo "=== Failed to generate kube-sa client certificates: Aborting ===" 1>&2
    exit 2
fi


###########################################################################################
# create cert for agrregated servers

# 1. metrics-server (aggregated apiserver, extention apiserver)
####    generate metrics-server client cert.  csr json file ( use kube profile of ca-config.json, server/client)
# kube user: metrics-server
# kube group: kube

cat <<EOF > kube-metrics-server-csr.json
{
    "CN": "metrics-server",
    "hosts": [
        "127.0.0.1","localhost",
        "$load_balancer_ip", "lb-node",
        $hosts_string,
        "$apiserver_service_cluster_ip_localvar",
        "$cluster_kube_dns_ip_localvar",
        "$pod_network_start_ip",

        "api",
        "kubernetes",
        "kubernetes.local",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local",
        "metrics-server",
        "metrics-server.local",
        "metrics-server.kube-system",
        "metrics-server.kube-system.svc",
        "metrics-server.kube-system.svc.cluster",
        "metrics-server.kube-system.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "kube",
            "OU": "internet"
        }
    ]
}
EOF


# debug use
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kube  kube-metrics-server-csr.json | cfssljson -bare  kube-metrics-server) >/dev/null 2>&1; then
    echo "=== Failed to generate metrics-server server certificates: Aborting ===" 1>&2
    exit 2
fi

#################################################################################################
# create client cert for accessing aggregated apiserver (extention apiserver)
#

# 1.1 client cert to access aggregated apiserver (type: client)
####    generate aggregated apiserver client cert csr json file ( use kube profile of ca-config.json, client)
# kube user: kube-aggregated-apiserver-client
# kube group: kube

#    "hosts": [
#    ],

cat <<EOF > kube-aggregated-apiserver-client-csr.json
{
    "CN": "kube-aggregated-apiserver-client",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shenzhen",
            "ST": "Shenzhen",
            "O": "system:masters",
            "OU": "internet"
        }
    ]
}
EOF


# debug use
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client kube-aggregated-apiserver-client-csr.json | cfssljson -bare kube-aggregated-apiserver-client) >/dev/null 2>&1; then
    echo "=== Failed to generate kube-apiserver-client client certificates: Aborting ===" 1>&2
    exit 2
fi


# debug trace log
#echo "finished gen kube-serviceaccount cert" >> trace.log
# end debug
