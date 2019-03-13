#!/bin/bash --login

set -o errexit
set -o nounset
set -o pipefail

# flush iptables
#iptables -F

# erase iptables
# iptables -X

# re-create default iptables rules by restarting iptables.service
#systemctl restart iptables.service

# restart kube-proxy.service to re-create kube-porxy (iptables, ipvs rules)
#systemctl restart kube-proxy.service

timestamp() {
  date +"- bootup iptables setting created on %D %T"
}

timestamp >> /var/log/bootup-iptables-setting.log
