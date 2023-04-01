
## kubernetes-generator

A simple script to generation of certificates, kubernetes config files, systemd files and kubernetes binarey file, etc.  required for binary deployment of kubernetes clusters.

### Changed

- Fixed Bug: Malformed path 👍
- Aug 6, 2022: Add Feature: Automatically generate RPM packages 👍
- May 31, 2023: Support debian/ubuntu and automatically generate deb package.

### Quick Start

#### Prerequisites

- If you cluster ip is other, you must edit script, to change `generate_openssl_config_file` function's openssl config setting.


```
bash < (curl -s https://raw.githubusercontent.com/cylonchau/kubernetes-generator/main/generator.s)
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

<img src="https://github.com/CylonChau/kubernetes-certificates-generator/raw/main/img1.png">