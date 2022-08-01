
## kubernetes-certificates-generator

A simple script to generation of certificates, kubernetes config files, systemd files, etc.  required for binary deployment of kubernetes clusters

### Changed

- Fixed Bug: Malformed path 👍
- Add Feature: Automatically generate RPM packages 👍

### Quick Start

#### Prerequisites

- Modify  openssl.conf and change it to the ip and domain you need at the bottom. The variable part is the domain name entered when generating the certificate, and the others are other access addresses required by the kubernetes cluster.
  - openssl.conf


```
git clone https://github.com/CylonChau/kubernetes-generator && cd kubernetes-generator
chmod +x generator.sh
./generator.sh
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