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


# enviroment variables for kubelet cert :
#
# 1. NODE_IP_CURRENT: ip address of current worker node
#    use - "{{ hostvars[inventory_hostname]['host_ip_address'] }}"
# 2. NODE_HOSTNAME_CURRENT: hostname of current worker node
#    use - "{{ inventory_hostname }}"
# 3. CERT_DIR: (tmp work directory to generate cert file)


# Caller should set in the ev:
# ARCH - what arch of cfssl should be downloaded
# Also the following will be respected

# parse environment variables for internal use

# current node parameters
node_ip_current="${NODE_IP_CURRENT:="${1}"}"
node_hostname_current="${NODE_HOSTNAME_CURRENT:="${1}"}"

# master nodes parameters
node_ips="${NODE_IPS:="${1}"}"
load_balancer_ip="${LOAD_BALANCER_IP:="${1}"}"
pod_network_start_ip="${POD_NETWORK_START_IP:="${1}"}"

# cluster service parameters
apiserver_service_cluster_ip_localvar="${APISERVER_SERVICE_CLUSTER_IP:="${1}"}"
cluster_kube_dns_ip_localvar="${CLUSTER_DNS_IP:="${1}"}"

node_dns="${NODE_DNS:=""}"

# system parameters
arch="${ARCH:-"linux-amd64"}"

#cert_group="${CERT_GROUP:="root"}"

#cert_dir="${CERT_DIR:-"/etc/cert-cache/kubernetes"}"
cert_dir="${CERT_DIR:="${1}"}"

# end env pre-parse


# The following certificate pairs are created:
#
#  - ( ca - the cluster's certificate authority - copy from master ca -  already)
#  - kubelet ( for kubelet server and client )

declare -a san_array=()

IFS=',' read -ra node_ips <<< "$node_ips"
for ip in "${node_ips[@]}"; do
    san_array+=(${ip})
done

IFS=',' read -ra node_dns <<< "$node_dns"
for dns in "${node_dns[@]}"; do
    san_array+=(${dns})
done

# end env parse stage 2

# add cfssl utility bin directory to path (/usr/local/bin)
#   - as basic bash path do not include /usr/local/bin which cfssl utility reside in
export PATH="$PATH:/usr/local/bin"

# enter work directory to create kube ca cert
cd "${cert_dir}"

# debug log
pwd > trace.log
echo ${PATH} >> trace.log
echo ${cert_dir} >> trace.log
echo ${arch} >> trace.log
#echo ${cert_group} >> trace.log
#echo ${master_ca_config_dir} >> trace.log
#echo ${master_ca_dir} >> trace.log
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

# end env parse

# set kube username and group 
cn_name_current="system:node:${node_hostname_current}"
o_name_use="system:nodes"

# debug trace log
#echo ${hosts_string} >> trace.log
# end log

####    generate kubelet csr json
cat <<EOF > kubelet-csr.json
{
    "CN": "${cn_name_current}",
    "hosts": [
       "127.0.0.1","localhost",
       "$node_ip_current",
       "$node_hostname_current",
       "$load_balancer_ip", "lb-node",
       "$pod_network_start_ip",  
       $hosts_string,
       "$apiserver_service_cluster_ip_localvar",
       "$cluster_kube_dns_ip_localvar"
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
            "O": "${o_name_use}",
            "OU": "internet"
        }
    ]
}
EOF


# debug use
# end debug

if ! (cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -hostname="$node_hostname_current,$node_hostname_current.local,$node_ip_current" -profile=kube kubelet-csr.json | cfssljson -bare kubelet) >/dev/null 2>&1; then
    echo "=== Failed to generate kubelet server and client certificates: Aborting ===" 1>&2
    exit 2
fi

chmod 0640 kubelet*
chmod 0640 *.log

#echo "finished gen kubelet cert" >> trace.log
# end debug

