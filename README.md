
## kubernetes-certificates-generator

A simple script to generation of certificates, kubernetes config files, systemd files, etc.  required for binary deployment of kubernetes clusters

### Quick Start

#### prerequisites

- Modify  openssl.conf and change it to the ip and domain you need at the bottom. The variable part is the domain name entered when generating the certificate, and the others are other access addresses required by the kubernetes cluster.


```
chmod +x generator
./generator
```

#### postrequisites

```
├── bin
│   ├── kubeadm
│   ├── kube-apiserver
│   ├── kube-controller-manager
│   ├── kubectl
│   ├── kubelet
│   ├── kube-proxy
│   └── kube-scheduler
├── cert
│   ├── etcd
│   │   ├── patches
│   │   └── pki
│   │       ├── apiserver-etcd.crt
│   │       ├── apiserver-etcd.key
│   │       ├── ca.crt
│   │       ├── ca.key
│   │       ├── client.crt
│   │       ├── client.key
│   │       ├── peer.crt
│   │       ├── peer.key
│   │       ├── server.crt
│   │       └── server.key
│   └── kubernetes
│       ├── front-proxy
│       │   ├── front-proxy-ca.crt
│       │   ├── front-proxy-ca.key
│       │   ├── front-proxy-client.crt
│       │   └── front-proxy-client.key
│       ├── ingress
│       │   ├── ingress-server.crt
│       │   ├── ingress-server.key
│       │   └── patches
│       ├── kubelet
│       │   ├── auth
│       │   └── pki
│       │       ├── ca.crt
│       │       ├── kube-proxy.crt
│       │       └── kube-proxy.key
│       ├── master
│       │   ├── auth
│       │   │   ├── admin.conf
│       │   │   ├── bootstrap.conf
│       │   │   ├── controller-manager.conf
│       │   │   ├── kube-proxy.conf
│       │   │   └── scheduler.conf
│       │   ├── pki
│       │   │   ├── apiserver.crt
│       │   │   ├── apiserver-etcd.crt
│       │   │   ├── apiserver-etcd.key
│       │   │   ├── apiserver.key
│       │   │   ├── apiserver-kubelet-client.crt
│       │   │   ├── apiserver-kubelet-client.key
│       │   │   ├── ca.crt
│       │   │   ├── ca.key
│       │   │   ├── front-proxy-ca.crt
│       │   │   ├── front-proxy-ca.key
│       │   │   ├── front-proxy-client.crt
│       │   │   ├── front-proxy-client.key
│       │   │   ├── kube-controller-manager.crt
│       │   │   ├── kube-controller-manager.key
│       │   │   ├── kube-scheduler.crt
│       │   │   ├── kube-scheduler.key
│       │   │   ├── sa.key
│       │   │   └── sa.pub
│       │   └── token.csv
│       ├── patches
│       └── pki
│           ├── ca.crt
│           └── ca.key
├── kubernetes
│   ├── kube-apiserver
│   ├── kube-controller-manager
│   ├── kubelet
│   ├── kubelet-config.yaml
│   ├── kube-proxy
│   ├── kube-proxy-config.yaml
│   └── kube-scheduler
├── rsyslog
│   └── kubernetes.conf
└── system
    ├── kube-apiserver.service
    ├── kube-controller-manager.service
    ├── kubelet.service
    ├── kube-proxy.service
    └── kube-scheduler.service
```

- certificate files
  - kubernetes-generate/certs/etcd, you can copy pki to /etc/etcd/
  - kubernetes-generate/certs/kubernetes,  you can copy to /etc/kubernetes/
- rsyslog config file, copy to /etc/rsyslog.d/, don't forget restart service rsyslog
  - kubernetes-generate/rsyslog/kubernetes.conf
- systemd files, copy to /usr/lib/systemd/system/
  - kubernetes-generate/system
- binary files, kubernetes binary file
  - kubernetes-generate/bin
- auth files, don't forget update kubernetes cluster ip to available ip
  - kubernetes-generate/kubernetes/master,kubelet/auth

![img1](https://github.com/CylonChau/kubernetes-certificates-generator/raw/main/img1.png)
