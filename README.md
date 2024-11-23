
## kubernetes-generator

A simple script to generation of certificates, kubernetes config files, systemd files and kubernetes binarey file, etc.  required for binary deployment of kubernetes clusters.

### Changed

- Fixed Bug: Malformed path
- Aug 6, 2022: Add Feature: Automatically generate RPM packages
- Mar 31, 2023: Support debian/ubuntu and automatically generate deb package.
- May 26, 2023: Fixed Centos generation RPM package issue.
- Nov 24, 2024: 
  - Add deb hook scripts (permission and pre-create 'kube' user)
  - Improvement function
  - Fixed deb systemd unit files for kubernetes service.s

### Quick Start

#### Prerequisites

- If you cluster ip is other, you must edit script, to change `generate_openssl_config_file` function's openssl config setting.


```
bash <(curl -s https://raw.githubusercontent.com/cylonchau/kubernetes-generator/main/generator.sh)
```

Must update your kubernetes cluster ip or etcd cluster ip input to bash script after execute bash script

For example 

In generator.sh change following 

```ini
# change your etcd cluster ip and domain
[ etcd_server_and_peer_dns ]
DNS.1 = \${ENV::BASE_DOMAIN}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 127.0.0.5
# custom define
IP.3 = 10.0.0.3
IP.4 = 10.0.0.4
IP.5 = 10.0.0.5

# change your kubernetes apiserver cert ip and domain
[ apiserver_names ]
DNS.1 = \${ENV::CLUSTER_NAME}-\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
DNS.3 = kubernetes
DNS.4 = kubernetes.default
DNS.5 = kubernetes.default.svc
DNS.6 = kubernetes.default.svc.cluster.local
IP.1 = \${ENV::KUBEAPISERVER_CLUSTER_IP}
# custom define
IP.2 = 10.0.0.4
IP.3 = 10.0.0.5
IP.4 = 10.0.0.6

# change your kubernetes master cpmponent cert ip and domain
[ master_component_names ]
DNS.1 = \${ENV::K8S_MASTER_NAME}.\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
IP.1 = 127.0.0.1
# custom define
IP.2 = 10.0.0.4
IP.3 = 10.0.0.5
IP.4 = 10.0.0.6

# change your etcd cluster ip and domain used for etcd client
# used for etcd_client
[ etcd_client ]
DNS.1 = localhost
IP.1 = 127.0.0.1
# custom define
IP.2 = 10.0.0.5
IP.3 = 10.0.0.4
IP.4 = 10.0.0.6

# Don't need change following configuration
# used for kubelet kube-proxy
[ kube_node ]
DNS.1 = \${ENV::CLUSTER_NAME}-\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
IP.1 = \${ENV::KUBEAPISERVER_CLUSTER_IP}
```

#### Postrequisites

- certificate files
  - output-generate/certs/etcd, you can copy pki to /etc/etcd/
  - output-generate/certs/kubernetes,  you can copy to /etc/kubernetes/
- rsyslog config file, copy to /etc/rsyslog.d/, don't forget restart service rsyslog
  - output-generate/rsyslog/kubernetes.conf
- systemd files, copy to /usr/lib/systemd/system/
  - output-generate/system
- binary files, kubernetes binary file
  - output-generate/bin
- auth files, don't forget update kubernetes cluster ip to available ip
  - output-generate/kubernetes/master,kubelet/auth


```
cp -a output-generate/cert/etcd/pki/ /etc/etcd/
cp -a output-generate/cert/kubernetes/master/* /etc/kubernetes/
cp -a output-generate/kubernetes/* /etc/kubernetes/


cp output-generate/rsyslog/kubernetes.conf /etc/rsyslog.d/
systemctl restart rsyslog

cp -a output-generate/system/* /usr/lib/systemd/system/
systemctl daemon-reload

useradd kube -s /sbin/nologin -M
chown kube /etc/kubernetes -R
```

