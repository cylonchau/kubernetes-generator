
## kubernetes-certificates-generator

A simple script to generation of certificates, kubernetes config files, systemd files, etc.  required for binary deployment of kubernetes clusters

### Quick Start

#### Prerequisites

- Modify  openssl.conf and change it to the ip and domain you need at the bottom. The variable part is the domain name entered when generating the certificate, and the others are other access addresses required by the kubernetes cluster.


```
git clone https://github.com/CylonChau/kubernetes-certificates-generator && cd kubernetes-certificates-generator
chmod +x generator
./generator
```

or

```
bash <(curl -s -L https://github.com/CylonChau/kubernetes-certificates-generator/raw/main/generator.sh)
```

#### Postrequisites

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


```
cp -a kubernetes-generate/cert/etcd/pki/ /etc/etcd/
cp -a kubernetes-generate/cert/kubernetes/master/* /etc/kubernetes/
cp -a kubernetes-generate/kubernetes/* /etc/kubernetes/


cp kubernetes-generate/rsyslog/kubernetes.conf /etc/rsyslog.d/
systemctl restart rsyslog

cp -a kubernetes-generate/system/* /usr/lib/systemd/system/
systemctl daemon-reload

useradd kube -s /sbin/nologin -M
chown kube /etc/kubernetes -R
```



<img src="https://github.com/CylonChau/kubernetes-certificates-generator/raw/main/img1.png">