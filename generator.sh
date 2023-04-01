#!/bin/bash -e

set -e
NotFount=204
IllegalContent=205
CommondNotFound=127

ROOT=$(cd $(dirname $0); pwd)
export ROOT


function generate_openssl_config_file(){
    [ -f "openssl.conf" ] || cat > ${ROOT}/openssl.conf << EOF
# environment variable values
BASE_DOMAIN=
CLUSTER_NAME=
CERT_DIR=
APISERVER_CLUSTER_IP=
MASTER_NAME=

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ${ENV::CERT_DIR}
certs             = $dir
crl_dir           = $dir/crl
new_certs_dir     = $dir
database          = $dir/index.txt
serial            = $dir/serial
# certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate-ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
# Allow the CA to sign a range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# `man req`
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[ req_distinguished_name ]
countryName                    = Country Name (2 letter code)
stateOrProvinceName            = State or Province Name
localityName                   = Locality Name
0.organizationName             = Organization Name
organizationalUnitName         = Organizational Unit Name
commonName                     = Common Name

# Certificate extensions (`man x509v3_config`)

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @etcd_client

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[ identity_server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS.1:tectonic-identity-api.tectonic-system.svc.cluster.local

[ etcd_server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @req_dns

[ etcd_peer_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @req_dns

[ apiserver_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @apiserver_names

[ master_component_client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @master_names

[req_dns]
DNS.1 = ${ENV::BASE_DOMAIN}
DNS.2 = localhost
IP.1 = 10.0.0.5
IP.2 = 127.0.0.1

[apiserver_names]
DNS.1 = ${ENV::CLUSTER_NAME}-${ENV::BASE_DOMAIN}
DNS.2 = ${ENV::BASE_DOMAIN}
DNS.3 = kubernetes
DNS.4 = kubernetes.default
DNS.5 = kubernetes.default.svc
DNS.6 = kubernetes.default.svc.cluster.local
IP.1 = ${ENV::APISERVER_CLUSTER_IP}
IP.2 = 10.0.0.5


[ master_names ]
DNS.1 = ${ENV::MASTER_NAME}.${ENV::BASE_DOMAIN}
DNS.2 = ${ENV::BASE_DOMAIN}
IP.1 = 10.0.0.5

[ etcd_client ]
DNS.1 = localhost
IP.1 = 10.0.0.5
IP.2 = 10.0.0.4
IP.3 = 10.0.0.6
IP.4 = 127.0.0.1
EOF
}

function cert_kubernetes(){
    echo -n -e "\n\033[41;37mLet's configure some parameters below to prepare etcd certificate generation.\033[0m\n\n"
    read -p "Pls Enter Kubernetes Domain Name [my-k8s.k8s.io]: " BASE_DOMAIN
    BASE_DOMAIN=${BASE_DOMAIN:-my-k8s.k8s.io}

    read -p "Pls Enter Kubernetes Cluster Name [kubernetes]: " CLUSTER_NAME
    echo -n -e "Enter the IP Address in kubeconfig \n of the Kubernetes API Server IP [10.96.0.1]: "
    read  APISERVER_CLUSTER_IP
    read -p "Pls Enter Master servers name [master01 master02]: " MASTERS

    read -p "Pls Enter kubeconfig's server ip [${BASE_DOMAIN}]: " KUBECONFIG_SERVER_IP
    KUBECONFIG_SERVER_IP=${KUBECONFIG_SERVER_IP:-${BASE_DOMAIN}}

    CLUSTER_NAME=${CLUSTER_NAME:-kubernetes}
    APISERVER_CLUSTER_IP=${APISERVER_CLUSTER_IP:-10.96.0.1}
    MASTERS=${MASTERS:-"master01 master02"}

    read -p "Pls Enter CA Common Name [k8s-ca]: " CERT_CN
    CERT_CN=${CERT_CN:-k8s-ca}

    read -p "Pls Enter Certificate validity period [3650]: " EXPIRED_DAYS
    EXPIRED_DAYS=${EXPIRED_DAYS:-3650}

    export BASE_DOMAIN CLUSTER_NAME APISERVER_CLUSTER_IP MASTERS CERT_CN EXPIRED_DAYS KUBECONFIG_SERVER_IP

    export CA_CERT="$CERT_DIR/ca.crt"
    export CA_KEY="$CERT_DIR/ca.key"
    if [ -f "$CA_CERT" -a -f "$CA_KEY" ]; then
        echo "Using the CA: $CA_CERT and $CA_KEY"
        read -p "pause" A
    else
        echo "Generating CA key and self signed cert."
        openssl genrsa -out $CERT_DIR/ca.key 2048
        openssl req -config openssl.conf \
            -new -x509 -days 3650 -sha256 \
            -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt \
        -subj "/CN=${CERT_CN}"
    fi
}

function cert_etcd(){
    echo -n -e "\n\033[41;37mLet's configure some parameters below to prepare etcd certificate generation.\033[0m\n\n"
    read -p "Pls Enter etcd Domain Name [my-etcd]: " BASE_DOMAIN
    BASE_DOMAIN=${BASE_DOMAIN:-my-etcd}

    read -p "Pls Enter Organization Name [chinamobile]: " CERT_O
    CERT_O=${CERT_O:-chinamobile}

    read -p "Pls Enter CA Common Name [etcd-ca]: " CERT_CN
    CERT_CN=${CERT_CN:-etcd-ca}

    read -p "Pls Enter Certificate validity period [3650]: " EXPIRED_DAYS
    EXPIRED_DAYS=${EXPIRED_DAYS:-3650}

    export BASE_DOMAIN CERT_O CERT_CN EXPIRED_DAYS
}

function set_cert_evn(){
    DIR=${DIR:-generate}
    if [ ${#} -eq 1 ]; then
        DIR="${WORK_DIR}/cert/$1"
    fi
    export DIR
    export CERT_DIR=$DIR/pki
    mkdir -p $CERT_DIR
    PATCHES=$DIR/patches
    mkdir -p $PATCHES

    # Configure expected OpenSSL CA configs.

    touch $CERT_DIR/index
    touch $CERT_DIR/index.txt
    touch $CERT_DIR/index.txt.attr
    echo 1000 > $CERT_DIR/serial
    # Sign multiple certs for the same CN
    echo "unique_subject = no" > $CERT_DIR/index.txt.attr

}

function openssl_req() {
    openssl genrsa -out ${1}/${2}.key 2048
    echo "Generating ${1}/${2}.csr"
    openssl req -config openssl.conf -new -sha256 \
        -key ${1}/${2}.key -out ${1}/${2}.csr -subj "$3"
}

function openssl_sign() {
    echo "Generating ${3}/${4}.crt"
    openssl ca -batch -config openssl.conf -extensions $5 -days ${EXPIRED_DAYS} -notext \
        -md sha256 -in ${3}/${4}.csr -out ${3}/${4}.crt \
        -cert ${1} -keyfile ${2}
}

# $1 cluster_name
# $2 username
# $3 filename
# $4 client-ca
# $5 client-key
function kubeconfig_approve(){
    case $2 in
    "system:kube-proxy"|"system:bootstrapper")
        export Client_CERT_DIR=${kubelet_dir}
        ;;
    *)
        export Client_CERT_DIR=${master_dir}
        ;;
    esac
    ${WORK_DIR}/bin/kubectl config set-cluster ${1} \
        --embed-certs=true \
        --server=https://${KUBECONFIG_SERVER_IP}:6443 \
        --certificate-authority=$CA_CERT \
        --kubeconfig=${Client_CERT_DIR}/auth/${3}

    case $2 in
    "system:bootstrapper")
        ${WORK_DIR}/bin/kubectl config set-credentials ${2} \
            --token=${BOOTSTRAP_TOKEN} \
            --kubeconfig=${Client_CERT_DIR}/auth/${3}
        ;;
    *)
        ${WORK_DIR}/bin/kubectl config set-credentials ${2} \
            --embed-certs=true \
            --client-certificate=${Client_CERT_DIR}/pki/${4} \
            --client-key=${Client_CERT_DIR}/pki/${5} \
            --kubeconfig=${Client_CERT_DIR}/auth/${3}
        ;;
    esac

    ${WORK_DIR}/bin/kubectl config set-context ${2}@${1} \
        --user=${2} \
        --cluster=${1} \
        --kubeconfig=${Client_CERT_DIR}/auth/${3}

    ${WORK_DIR}/bin/kubectl config use-context ${2}@${1}  \
        --kubeconfig=${Client_CERT_DIR}/auth/${3}
}

function generate_kubernetes_certificates() {
    # If supplied, generate a new etcd CA and associated certs.
    if [ !-n $ETCD_CERTS_DIR ]; then
       export ETCD_CERTS_DIR=${WORK_DIR}/cert/etcd
    fi

    if [ -n $FRONT_PROXY_CA_CERT ]; then
        front_proxy_dir=${DIR}/front-proxy
        if [ ! -d "$front_proxy_dir" ]; then
        mkdir $front_proxy_dir
        fi

        openssl genrsa -out ${front_proxy_dir}/front-proxy-ca.key 2048
        openssl req -config openssl.conf \
            -new -x509 -days ${EXPIRED_DAYS} -sha256 \
            -key ${front_proxy_dir}/front-proxy-ca.key \
            -out ${front_proxy_dir}/front-proxy-ca.crt -subj "/CN=front-proxy-ca"

        openssl_req ${front_proxy_dir} front-proxy-client "/CN=front-proxy-client"

        openssl_sign ${front_proxy_dir}/front-proxy-ca.crt ${front_proxy_dir}/front-proxy-ca.key ${front_proxy_dir} front-proxy-client client_cert
        rm -f ${front_proxy_dir}/*.csr
    fi

    # BootStrap Token
    export BOOTSTRAP_TOKEN="$(head -c 6 /dev/urandom | md5sum | head -c 6).$(head -c 16 /dev/urandom | md5sum | head -c 16)"
    echo "$BOOTSTRAP_TOKEN,\"system:bootstrapper\",10001,\"system:bootstrappers\"" > /tmp/token.csv

    # Generate and sihn CSRs for all components of masters
    for master in $MASTERS; do
        master_dir="${DIR}/${master}"

        if [ ! -d "${master_dir}" ]; then
            mkdir -p ${master_dir}/{auth,pki}
        fi

        export MASTER_NAME=${master}

        openssl_req "${master_dir}/pki" apiserver "/CN=kube-apiserver"
        openssl_req "${master_dir}/pki" kube-controller-manager "/CN=system:kube-controller-manager"
        openssl_req "${master_dir}/pki" kube-scheduler "/CN=system:kube-scheduler"
        openssl_req "${master_dir}/pki" apiserver-kubelet-client "/CN=kube-apiserver-kubelet-client/O=system:masters"

        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" apiserver apiserver_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" kube-controller-manager master_component_client_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" kube-scheduler master_component_client_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" apiserver-kubelet-client client_cert
        rm -f ${master_dir}/pki/*.csr

        # Copy CA key and cert file to ${master_dir}
        cp $CA_CERT $CA_KEY ${master_dir}/pki/

        # Copy front-proxy CA key and cert file to ${master_dir}
        cp $front_proxy_dir/front-proxy* ${master_dir}/pki/

        # echo "Generating the ServiceAccount key for apiserver"
        openssl ecparam -name secp521r1 -genkey -noout -out ${master_dir}/pki/sa.key
        openssl ec -in ${master_dir}/pki/sa.key -outform PEM -pubout -out ${master_dir}/pki/sa.pub

        # echo "Copy token file"
        cp /tmp/token.csv ${master_dir}/

        if [ -d "$ETCD_CERTS_DIR" ]; then
            # echo "Copy etcd client key and certs"
            cp $ETCD_CERTS_DIR/pki/apiserver-etcd.{key,crt} ${master_dir}/pki/
        fi
        # echo "Generating kubeconfig for kube-controller-manager"
        # $1 cluster_name
        # $2 username
        # $3 filename
        # $4 client-ca
        # $5 client-key
        kubeconfig_approve ${CLUSTER_NAME} system:kube-controller-manager controller-manager.conf kube-controller-manager.crt kube-controller-manager.key

        # echo "Generating kubeconfig for kube-scheduler"
        kubeconfig_approve ${CLUSTER_NAME} system:kube-scheduler scheduler.conf kube-scheduler.crt kube-scheduler.key

        # echo "Generating kubeconfig for Cluster Admin"
        kubeconfig_approve ${CLUSTER_NAME} k8s-admin admin.conf apiserver-kubelet-client.crt apiserver-kubelet-client.key
    done

    # Generate key and cert for kubelet
    kubelet_dir=${DIR}/kubelet
    mkdir -p ${kubelet_dir}/{pki,auth}

    openssl_req ${kubelet_dir}/pki kube-proxy "/CN=system:kube-proxy"
    openssl_sign $CA_CERT $CA_KEY ${kubelet_dir}/pki kube-proxy client_cert

    rm -f ${kubelet_dir}/pki/kube-proxy.csr

    # Copy CA Cert to Node
    cp $CA_CERT ${kubelet_dir}/pki/

    kubeconfig_approve ${CLUSTER_NAME} system:kube-proxy kube-proxy.conf kube-proxy.crt kube-proxy.key

    kubeconfig_approve ${CLUSTER_NAME} system:bootstrapper bootstrap.conf


    # Generate key and cert for ingress
    ingress_dir=${DIR}/ingress
    mkdir -p ${DIR}/ingress/patches

    openssl_req ${ingress_dir} ingress-server "/CN=${CLUSTER_NAME}.${BASE_DOMAIN}"
    openssl_sign $CA_CERT $CA_KEY ${ingress_dir} ingress-server server_cert
    rm -f ${ingress_dir}/*.csr

    # Generate secret patches. We include the metadata here so
    # `kubectl patch -f ( file ) -p $( cat ( file ) )` works.


    # Clean up openssl config
    rm -f $CERT_DIR/index*
    rm -f $CERT_DIR/100*
    rm -f $CERT_DIR/serial*
    rm -f /tmp/token.csv
}


function generate_etcd_certificates() {
    if [ -z "$CA_KEY" -o -z "$CA_CERT" ]; then
        openssl genrsa -out $CERT_DIR/ca.key 2048
        openssl req -config openssl.conf \
            -new -x509 -days ${EXPIRED_DAYS} -sha256 \
            -key $CERT_DIR/ca.key -extensions v3_ca \
            -out $CERT_DIR/ca.crt -subj "/CN=${CERT_CN}"
        export CA_KEY="$CERT_DIR/ca.key"
        export CA_CERT="$CERT_DIR/ca.crt"
    fi

    openssl_req $CERT_DIR peer "/O=${CERT_O}/CN=$BASE_DOMAIN"
    openssl_req $CERT_DIR server "/O=${CERT_O}/CN=$BASE_DOMAIN"
    openssl_req $CERT_DIR apiserver-etcd "/O=${CERT_O}/CN=$BASE_DOMAIN"
    openssl_req $CERT_DIR client "/O=${CERT_O}/CN=$BASE_DOMAIN"

    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR peer etcd_peer_cert
    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR server etcd_server_cert
    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR apiserver-etcd client_cert
    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR client client_cert

    # Add debug information to directories
    #for CERT in $CERT_DIR/*.crt; do
    #    openssl x509 -in $CERT -noout -text > "${CERT%.crt}.txt"
    #done

    # Clean up openssl config
    rm $CERT_DIR/index*
    rm $CERT_DIR/100*
    rm $CERT_DIR/serial*
    rm $CERT_DIR/*.csr
}

function generate_certificates(){
    set_cert_evn etcd
    cert_etcd
    generate_etcd_certificates
    set_cert_evn kubernetes
    cert_kubernetes
    generate_kubernetes_certificates
}

######################################################################################
#                download and extract kubernetes bin file.                           #
######################################################################################

function download_kube(){
    read -p "Please enter the kubernetes version to download [1.18.20]: " Kubernetes_Version
    export Kubernetes_Version=${Kubernetes_Version:-1.18.20}

    export build_arch=""
    case "`uname -m`" in
    x86*)
        build_arch="amd64"
        ;;
    *arm*)
        build_arch="arm64"
        ;;

    esac

    export KubernetesDownloadUrl="https://dl.k8s.io/v${Kubernetes_Version}/kubernetes-server-linux-${build_arch}.tar.gz"
    code=$(curl -L -I -w %{http_code} ${KubernetesDownloadUrl} -o /dev/null -s)

    export TMP_DIR=${WORK_DIR}/tmp
    [ -d ${TMP_DIR} ] && rm -fr ${TMP_DIR}
    mkdir -p ${TMP_DIR}
    case "$code" in
    404|"404")
        echo -n -e "Kubernetes version v${Kubernetes_Version} Not Found.\n"
        exit ${NotFount}
        ;;
    *)
        echo -n -e "\n\033[41;37mBegin download kubernetes v${Kubernetes_Version}.\033[0m\n\n"
        wget -t 3 -P ${TMP_DIR} ${KubernetesDownloadUrl}
        ;;
    esac
}

function extract_kube(){
    export ExtratDir=${TMP_DIR}/kubernetes/server/bin/
    tar xf ${TMP_DIR}/kubernetes-server-linux-amd64.tar.gz -C ${TMP_DIR}/
    rm -f ${TMP_DIR}/kubernetes-server-linux-amd64.tar.gz

    find ${TMP_DIR}/kubernetes/server/bin/ -type f \
    ! -name "kube-apiserver" \
    ! -name "kube-controller-manager" \
    ! -name "kube-scheduler" \
    ! -name "kube-proxy" \
    ! -name "kubelet" \
    ! -name "kubectl" \
    ! -name "kubeadm" \
    -exec rm {} +

    mv ${TMP_DIR}/kubernetes/server/bin ${WORK_DIR}/
    rm -fr ${TMP_DIR}
}


######################################################################################
#                         initial kubernetes config files.                           #
######################################################################################


function clean_bin(){
    rm -fr ${WORK_DIR}/bin
}

function action_initial(){
    echo -n -e "\n\033[41;37mLet's configure some parameters below to prepare the initial kubernetes config file and systemd file. \033[0m\n"

    echo -n -e "    1.master.\n    2.node\n    3.all(master and node).\n"
    read -p "Please enter the which to install [3]: " ROLE_PACKAGE
    export ROLE_PACKAGE=${ROLE_PACKAGE:-3}

    case "$ROLE_PACKAGE" in
    1)
        init_server
        init_syslog_conig_file
        ;;
    2)
        init_client
        init_syslog_conig_file
        ;;
    3)
        init_server
        init_client
        init_syslog_conig_file
        ;;
    *)
        echo -e "\033[41;37millegal content \"${ROLE_PACKAGE}\".\033[0m"
        exit $IllegalContent
        ;;
    esac
}

function init_server(){
    echo -e "\n"
    read -p "Please enter the binary file path of server [/usr/local/bin]: " SERVER_BIN_DIR
    export SERVER_BIN_DIR=${SERVER_BIN_DIR:-/usr/local/bin}
    init_apiserver
    init_controller_manager
    init_scheduler
}

######################################################################################
#                  initial kubernetes server config files.                           #
######################################################################################


function init_apiserver(){
    echo -e -n "\nLet's configure some parameters below to prepare to generate
        the \033[41;37mkube-apiserver\033[0m config file.\n\n"

    read -p "Please enter the \"kube-apiserver\" service name [kube-apiserver]: " APISERV_NAME
    export APISERV_NAME=${APISERV_NAME:-kube-apiserver}

    read -p "Please enter cluster IP range [10.96.0.0/12]: " IP_RANGE
    export IP_RANGE=${IP_RANGE:-10.96.0.0/12}

    read -p "Please enter cluster cetaficate file path [/etc/kubernetes/pki]: " CA_PATH
    export CA_PATH=${CA_PATH:-/etc/kubernetes/pki}

    read -p "Please enter cluster token file path [/etc/kubernetes]: " TOKEN_PATH
    export TOKEN_PATH=${TOKEN_PATH:-/etc/kubernetes}

    read -p "Please enter etcd ca file path [/etc/etcd/pki]: " ETCD_CA
    export ETCD_CA=${ETCD_CA:-/etc/etcd/pki}

    read -p "Please enter kube-apiserver listen addr [0.0.0.0]: " APISERV_LISTEN
    export APISERV_LISTEN=${APISERV_LISTEN:-0.0.0.0}

    read -p "Do you allow privileged containers? If true, allow privileged containers. [default=false]: " ALLOW_PRIVILEGED
    export ALLOW_PRIVILEGED=${ALLOW_PRIVILEGED:-false}

    cat > ${CONF_DIR}/${APISERV_NAME} << EOF
# kubernetes system config
#
# The following values are used to configure the kube-apiserver
#

# The address on the local server to listen to.
KUBE_API_ADDRESS="--advertise-address=${APISERV_LISTEN}"

# The port on the local server to listen on.
KUBE_API_PORT="--secure-port=6443"

# Comma separated list of nodes in the etcd cluster
# KUBE_ETCD_SERVERS="--etcd-servers=https://10.0.0.4:2379,https://10.0.0.5:2379,https://10.0.0.6:2379"
KUBE_ETCD_SERVERS="--etcd-servers=https://"

# Address range to use for services
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=${IP_RANGE}"

# default admission control policies
KUBE_ADMISSION_CONTROL="--enable-admission-plugins=NodeRestriction"

# Add your own need parameters!
KUBE_API_ARGS="--allow-privileged=${ALLOW_PRIVILEGED} \\
    --v=0 \\
    --logtostderr=true \\
    --authorization-mode=Node,RBAC \\
    --enable-bootstrap-token-auth=true \\
    --client-ca-file=${CA_PATH}/ca.crt \\
    --etcd-cafile=${ETCD_CA}/ca.crt \\
    --etcd-certfile=${CA_PATH}/apiserver-etcd.crt \\
    --etcd-keyfile=${CA_PATH}/apiserver-etcd.key \\
    --kubelet-client-certificate=${CA_PATH}/apiserver-kubelet-client.crt \\
    --kubelet-client-key=${CA_PATH}/apiserver-kubelet-client.key \\
    --kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname \\
    --proxy-client-cert-file=${CA_PATH}/front-proxy-client.crt \\
    --proxy-client-key-file=${CA_PATH}/front-proxy-client.key \\
    --requestheader-allowed-names=front-proxy-client \\
    --requestheader-client-ca-file=${CA_PATH}/front-proxy-ca.crt \\
    --requestheader-extra-headers-prefix=X-Remote-Extra- \\
    --requestheader-group-headers=X-Remote-Group \\
    --requestheader-username-headers=X-Remote-User \\
    --service-account-key-file=${CA_PATH}/sa.pub \\
    --tls-cert-file=${CA_PATH}/apiserver.crt \\
    --tls-private-key-file=${CA_PATH}/apiserver.key \\
    --token-auth-file=${TOKEN_PATH}/token.csv"
EOF
    cat > ${SYSTEMD_DIR}/${APISERV_NAME}.service << EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${APISERV_NAME}
User=kube
ExecStart=${SERVER_BIN_DIR}/${APISERV_NAME} \\
        \$KUBE_ETCD_SERVERS \\
        \$KUBE_API_ADDRESS \\
        \$KUBE_API_PORT \\
        \$KUBE_SERVICE_ADDRESSES \\
        \$KUBELET_PORT \\
        \$KUBE_API_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${APISERV_NAME}

[Install]
WantedBy=multi-user.target
EOF
}

function init_controller_manager(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkube-controller-manager\033[0m config file.\n\n"

    read -p "Please enter cluster IP cidr [10.244.0.0/16]: " CM_CIDR
    export CM_CIDR=${CM_CIDR:-10.244.0.0/16}

    read -p "Please enter the \"kube-controller-manager\" service name [kube-controller-manager]: " CONTRO_NAME
    export CONTRO_NAME=${CONTRO_NAME:-kube-controller-manager}

    cat > ${CONF_DIR}/${CONTRO_NAME} << EOF
# The following values are used to configure the kubernetes controller-manager
#
# defaults from config and apiserver should be adequate

# You can add your configurion own!
KUBE_CONTROLLER_MANAGER_ARGS="--v=0 \\
    --logtostderr=true \\
    --allocate-node-cidrs=true \\
    --authentication-kubeconfig=/etc/kubernetes/auth/controller-manager.conf \\
    --authorization-kubeconfig=/etc/kubernetes/auth/controller-manager.conf \\
    --client-ca-file=${CA_PATH}/ca.crt \\
    --root-ca-file=${CA_PATH}/ca.crt \\
    --cluster-cidr=${CM_CIDR} \\
    --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt \\
    --cluster-signing-key-file=/etc/kubernetes/pki/ca.key \\
    --controllers=*,bootstrapsigner,tokencleaner \\
    --kubeconfig=/etc/kubernetes/auth/controller-manager.conf \\
    --leader-elect=true \\
    --node-cidr-mask-size=24 \\
    --requestheader-client-ca-file=${CA_PATH}/front-proxy-ca.crt \\
    --service-account-private-key-file=/etc/kubernetes/pki/sa.key \\
    --use-service-account-credentials=true"
EOF

    cat > ${SYSTEMD_DIR}/${CONTRO_NAME}.service << EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${CONTRO_NAME}
User=kube
ExecStart=${SERVER_BIN_DIR}/${CONTRO_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${CONTRO_NAME}

[Install]
WantedBy=multi-user.target
EOF
}


function init_scheduler(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkube-scheduler\033[0m config file.\n\n"

    read -p "Please enter the \"kube-scheduler\" service name [kube-scheduler]: " SCHEDR_NAME
    export SCHEDR_NAME=${SCHEDR_NAME:-kube-scheduler}

    cat > ${CONF_DIR}/${SCHEDR_NAME} << EOF
# kubernetes scheduler config
#
# default config should be adequate
#
# You can add your configurtion own!
KUBE_SCHEDULER_ARGS="--v=0 \\
    --logtostderr=true \\
    --kubeconfig=/etc/kubernetes/auth/scheduler.conf"
EOF

    cat > ${SYSTEMD_DIR}/${SCHEDR_NAME}.service << EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/${SCHEDR_NAME}
User=kube
ExecStart=${SERVER_BIN_DIR}/${SCHEDR_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${SCHEDR_NAME}

[Install]
WantedBy=multi-user.target
EOF
}


######################################################################################
#                    initial kubernetes node config files.                           #
######################################################################################


function init_client(){
    echo -e "\n"
    read -p "Please enter the binary file path of node [/usr/local/bin]: " NODE_BIN_DIR
    export NODE_BIN_DIR=${NODE_BIN_DIR:-/usr/local/bin}
    init_kubelet
    init_proxy
}

function init_kubelet(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkubelet\033[0m config file.\n\n"

    read -p "Please enter the \"kubelet\" service name [kubelet]: " LET_NAME
    export LET_NAME=${LET_NAME:-kubelet}

    read -p "Please enter the \"kubelet\" working directory [/var/lib/kubelet]: " LET_CONF_DIR
    export LET_CONF_DIR=${LET_CONF_DIR:-/var/lib/kubelet}

    # read -p "Please enter kubeconfig path for the kubelet [/etc/kubernetes/auth]: " LET_KUBECONF_DIR
    # export LET_KUBECONF_DIR=${LET_KUBECONF_DIR:-/etc/kubernetes/auth}

    cat > ${CONF_DIR}/${LET_NAME} << EOF
# kubernetes kubelet config
#
# You can add your configuration own!
KUBELET_ARGS="--v=0 \\
    --logtostderr=true \\
    --network-plugin=cni \\
    --config=/etc/kubernetes/${LET_NAME}-config.yaml \\
    --kubeconfig=/etc/kubernetes/auth/${LET_NAME}.conf \\
    --bootstrap-kubeconfig=/etc/kubernetes/auth/bootstrap.conf"
EOF
    ${WORK_DIR}/bin/kubeadm config print init-defaults --component-configs KubeletConfiguration|grep -A 1000 'apiVersion: kubelet.config.k8s.io/v1beta1' > ${CONF_DIR}/${LET_NAME}-config.yaml
    sed -i 's@0s@20s@g' ${CONF_DIR}/${LET_NAME}-config.yaml

    cat > ${SYSTEMD_DIR}/${LET_NAME}.service << EOF
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=${LET_CONF_DIR}
EnvironmentFile=-/etc/kubernetes/${LET_NAME}
ExecStart=${NODE_BIN_DIR}/${LET_NAME} \\
    \$KUBELET_API_SERVER \\
    \$KUBELET_ADDRESS \\
    \$KUBELET_PORT \\
    \$KUBELET_HOSTNAME \\
    \$KUBELET_ARGS
Restart=on-failure
KillMode=process
RestartSec=10
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${LET_NAME}

[Install]
WantedBy=multi-user.target
EOF
}

function init_proxy(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkube-proxy\033[0m config file.\n\n"
    read -p "Please enter the \"kube-proxy\" service name [kube-proxy]: " PROXY_NAME
    export PROXY_NAME=${PROXY_NAME:-kube-proxy}

    cat > ${CONF_DIR}/${PROXY_NAME} << EOF
# kubernetes proxy config
#
# You can add your configuration own!
KUBE_PROXY_ARGS="--v=0 \\
    --logtostderr=true \\
    --config=/etc/kubernetes/${PROXY_NAME}-config.yaml"
EOF
    ${WORK_DIR}/bin/kubeadm config print init-defaults --component-configs KubeProxyConfiguration|grep -A 1000 'kubeproxy.config.k8s.io/v1alpha1' > ${CONF_DIR}/${PROXY_NAME}-config.yaml
    sed -i "s@kubeconfig: /var/lib/kube-proxy/kubeconfig.conf@kubeconfig: /etc/kubernetes/${PROXY_NAME}.conf@g" ${CONF_DIR}/${PROXY_NAME}-config.yaml
    sed -i "s@clusterCIDR: \"\"@clusterCIDR: \"${CM_CIDR}\"@g" ${CONF_DIR}/${PROXY_NAME}-config.yaml

    cat > ${SYSTEMD_DIR}/${PROXY_NAME}.service << EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${PROXY_NAME}
ExecStart=${NODE_BIN_DIR}/${PROXY_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${PROXY_NAME}

[Install]
WantedBy=multi-user.target
EOF
}



######################################################################################
#                  initial rsyslog config files of kubernetes.                       #
######################################################################################


function init_syslog_conig_file(){
    cat > ${LOG_CONFIG_DIR}/kubernetes.conf << EOF
if (\$programname == '${APISERV_NAME}') then {
   action(type="omfile" file="/var/log/apiserver.log")
   stop
} else if (\$programname == '${SCHEDR_NAME}') then {
   action(type="omfile" file="/var/log/scheduler.log")
   stop
} else if (\$programname == '${CONTRO_NAME}') then {
   action(type="omfile" file="/var/log/controller-manager.log")
   stop
} else if (\$programname == '${LET_NAME}') then {
   action(type="omfile" file="/var/log/kubelet.log")
   stop
} else if (\$programname == '${PROXY_NAME}') then {
   action(type="omfile" file="/var/log/kube-proxy.log")
   stop
} else if (\$programname == 'etcd') then {
   action(type="omfile" file="/var/log/etcd.log")
   stop
}
EOF
}


######################################################################################
#                               clean temp directory.                                #
######################################################################################

function END(){
    echo -n -e "\n\033[31mThe certificate files is in ${WORK_DIR}/cert/. \033[0m\n"
    echo -n -e "\033[31mPlease copy the ${CONF_DIR} to /etc/. \033[0m\n"
    echo -n -e "\033[31mPlease copy the ${SYSTEMD_DIR} to /usr/lib/systemd/. \033[0m\n"
    echo -n -e "\033[31mPlease modify the kube-proxy config file ${CONF_DIR}/${PROXY_NAME}-config.yaml
        and kubelet config file ${CONF_DIR}/${LET_NAME}-config.yaml as required. \033[0m\n"
    echo -n -e "\033[31mPlease copy the ${LOG_CONFIG_DIR} to /etc/.
        Don't forget restart service rsyslog. \033[0m\n"
}


function set_env(){
    WORK_DIR=${WORK_DIR:-_output}
    if [ ${#} -eq 1 ]; then
        DIR="$1"
    fi
    [ -d ${ROOT}/_output ] && rm -fr ${ROOT}/_output
    export WORK_DIR=${ROOT}/_output
    export CONF_DIR=$WORK_DIR/kubernetes
    export SYSTEMD_DIR=$WORK_DIR/system
    export LOG_CONFIG_DIR=$WORK_DIR/rsyslog

    mkdir -p $CONF_DIR
    mkdir -p $SYSTEMD_DIR
    mkdir -p $LOG_CONFIG_DIR
}

######################################################################################
#                             generation linux package.                              #
######################################################################################

######################################################################################
#                               debian package process.                              #
######################################################################################

function deb_logic() {
    export DEB_WORK_DIR=${WORK_DIR}/DEBIAN

    ##############################################################
    # install kubectl to build root dir                          #
    ##############################################################
    export KUBECTL_BUILD_DIR=${DEB_WORK_DIR}/kubectl
    install -d ${KUBECTL_BUILD_DIR}/DEBIAN
    cat > ${KUBECTL_BUILD_DIR}/DEBIAN/control << EOF
Package: kubectl
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubectl is your cockpit to control Kubernetes, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
    install -d ${KUBECTL_BUILD_DIR}/usr/sbin
    cp -a ${WORK_DIR}/bin/kubectl ${KUBECTL_BUILD_DIR}/usr/sbin/


    #################################################################
    # install kubernetes control plane components to build root dir #
    #################################################################
    export KUBE_SERVER_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-server
    install -d ${KUBE_SERVER_BUILD_DIR}/DEBIAN
    cat > ${KUBE_SERVER_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-server
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-server is you kubernetes server, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF

    # server bin files
    DEB_SERVER_BIN_DIR=${KUBE_SERVER_BUILD_DIR}/${SERVER_BIN_DIR}
    install -d ${DEB_SERVER_BIN_DIR}
    cp -a ${WORK_DIR}/bin/{kube-apiserver,kube-controller-manager,kube-scheduler} ${DEB_SERVER_BIN_DIR}

    # server config files
    DEB_SERVER_CONFIG_DIR=${KUBE_SERVER_BUILD_DIR}/etc/kubernetes/
    install -d ${DEB_SERVER_CONFIG_DIR}
    cp -a ${WORK_DIR}/kubernetes/{kube-apiserver,kube-controller-manager,kube-scheduler} ${DEB_SERVER_CONFIG_DIR}

    # server systemd files
    DEB_SERVER_SYSTEMD_DIR=${KUBE_SERVER_BUILD_DIR}/usr/lib/system/systemd/
    install -d ${DEB_SERVER_SYSTEMD_DIR}
    cp -a ${WORK_DIR}/system/{kube-apiserver.service,kube-controller-manager.service,kube-scheduler.service} ${DEB_SERVER_SYSTEMD_DIR}


    ############################################################
    # install kubernetes worker components to build root dir   #
    ############################################################
    export KUBE_NODE_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-node
    install -d ${KUBE_NODE_BUILD_DIR}/DEBIAN
    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-node
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-node is your kubernetes node component, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
    
    # worker bin files
    DEB_WORKER_BIN_DIR=${KUBE_NODE_BUILD_DIR}/${NODE_BIN_DIR}
    install -d ${DEB_WORKER_BIN_DIR}
    cp -a ${WORK_DIR}/bin/{kubelet,kube-proxy} ${DEB_WORKER_BIN_DIR}

    # worker config files
    DEB_WORKER_CONFIG_DIR=${KUBE_NODE_BUILD_DIR}/etc/kubernetes
    install -d ${DEB_WORKER_CONFIG_DIR}
    cp -a ${WORK_DIR}/kubernetes/{kubelet,kubelet-config.yaml,kube-proxy,kube-proxy-config.yaml} ${DEB_WORKER_CONFIG_DIR}

    # worker systemd files
    DEB_WORKER_SYSTEMD_DIR=${KUBE_NODE_BUILD_DIR}/usr/lib/system/systemd/
    install -d ${DEB_WORKER_SYSTEMD_DIR}
    cp -a ${WORK_DIR}/system/{kubelet.service,kube-proxy.service} ${DEB_WORKER_SYSTEMD_DIR}
    install -d ${KUBE_NODE_BUILD_DIR}/var/lib/kubelet

   
    for master in $MASTERS; do
        ############################################################
        # install kubernetes-server-certificates to build root dir #
        ############################################################

        export KUBE_SERVER_CERT_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-server-certificates-${master}
        install -d ${KUBE_SERVER_CERT_BUILD_DIR}/DEBIAN
        cat > ${KUBE_SERVER_CERT_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-server-certificates-${master}
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-server-certificates is your kubernetes control plane components certs, generated using cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
        DEB_SERVER_CERT_DIR=${KUBE_SERVER_CERT_BUILD_DIR}/${TOKEN_PATH}
        install -d ${DEB_SERVER_CERT_DIR}
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/pki ${KUBE_SERVER_CERT_BUILD_DIR}/${CA_PATH}
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/token.csv ${DEB_SERVER_CERT_DIR}/

        install -d ${DEB_SERVER_CERT_DIR}/auth
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/auth/{controller-manager.conf,scheduler.conf} ${DEB_SERVER_CERT_DIR}/auth/
    

        #############################################################
        #  install kubernetes kubernetes-admincfg to build root dir #
        #############################################################

        export KUBE_ADMINCFG_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-admincfg-${master}
        install -d ${KUBE_ADMINCFG_BUILD_DIR}/DEBIAN
        cat > ${KUBE_ADMINCFG_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-admincfg-${master}
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-admincfg is your kubernetes cluster admin kubeconfig, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF

        DEB_ADMINCFG_DIR=${KUBE_ADMINCFG_BUILD_DIR}/etc/kubernetes/auth/
        install -d ${DEB_ADMINCFG_DIR}
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/auth/admin.conf ${DEB_ADMINCFG_DIR}
    done

    #############################################################
    # install kubernetes-node-certificates to build root dir
    #############################################################
    export KUBE_NODE_CERT_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-node-certificates
    install -d ${KUBE_NODE_CERT_BUILD_DIR}/DEBIAN
    cat > ${KUBE_NODE_CERT_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-node-certificates
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-node-certificates is your kubernetes worker components certs, generated using cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF

    DEB_WORKER_CERT_DIR=${KUBE_NODE_CERT_BUILD_DIR}/etc/kubernetes
    install -d ${DEB_WORKER_CERT_DIR}
    # kubelet
    cp -a ${WORK_DIR}/cert/kubernetes/kubelet/* ${DEB_WORKER_CERT_DIR}/



    #############################################################
    #            kubernetes-etcd-certificates                   #
    #############################################################

    export ETCD_CERT_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-etcd-certificates
    install -d ${ETCD_CERT_BUILD_DIR}/DEBIAN
    cat > ${ETCD_CERT_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-etcd-certificates
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes-etcd-certificates is your etcd cluster certs, generated using cylonchau's kubernetes-generator.
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
    # etcd certs
    install -d ${ETCD_CERT_BUILD_DIR}/etc/etcd
    cp -a ${WORK_DIR}/cert/etcd/pki ${ETCD_CERT_BUILD_DIR}/etc/etcd/



    #############################################################
    #                         kubelog                           #
    #############################################################

    export KUBE_LOG_BUILD_DIR=${DEB_WORK_DIR}/kubelog
    install -d ${KUBE_LOG_BUILD_DIR}/DEBIAN
    cat > ${KUBE_LOG_BUILD_DIR}/DEBIAN/control << EOF
Package: kubelog
Version: ${Kubernetes_Version}
Architecture: ${build_arch}
Description: kubernetes log collection configurtion file, generated using cylonchau's kubernetes-generator.
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF

    # kubernetes syslog format
    install -d ${KUBE_LOG_BUILD_DIR}/etc/rsyslog.d/
    cp -a ${WORK_DIR}/rsyslog/kubernetes.conf ${KUBE_LOG_BUILD_DIR}/etc/rsyslog.d/


    # generating deb package
    export DEBS_DIR=${WORK_DIR}/debs
    install -d ${DEBS_DIR}
    dpkg-deb --build ${KUBECTL_BUILD_DIR} ${DEBS_DIR}
    dpkg-deb --build ${KUBE_SERVER_BUILD_DIR} ${DEBS_DIR}
    dpkg-deb --build ${KUBE_NODE_BUILD_DIR} ${DEBS_DIR}
    dpkg-deb --build ${KUBE_NODE_CERT_BUILD_DIR} ${DEBS_DIR}
    dpkg-deb --build ${ETCD_CERT_BUILD_DIR} ${DEBS_DIR}
    dpkg-deb --build ${KUBE_LOG_BUILD_DIR} ${DEBS_DIR}

    for master in $MASTERS; do
        export KUBE_SERVER_CERTS_BUILD=${DEB_WORK_DIR}/kubernetes-server-certificates-${master}
        dpkg-deb --build ${KUBE_SERVER_CERTS_BUILD} ${DEBS_DIR}

        export KUBE_ADMINCFGS_BUILD=${DEB_WORK_DIR}/kubernetes-admincfg-${master}
        dpkg-deb --build ${KUBE_ADMINCFGS_BUILD} ${DEBS_DIR}
    done
}


######################################################################################
#                               redhat package process.                              #
######################################################################################


function rpm_logic() {
    cp ${LOG_CONFIG_DIR}/kubernetes.conf ${RPM_WORK_DIR}/SOURCES/
    # server cert files
    tmpnum=0
    for n in `ls -tr -I pki -I patches -I ingress -I front-proxy -I kubelet ${WORK_DIR}/cert/kubernetes/`;
    do
        if [ ${tmpnum} == 0 ]
        then
            export CERT_NAME=${n}
        fi
        [ -d ${RPM_WORK_DIR}/SOURCES/certs/${n} ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/certs/${n}
        cp -a ${WORK_DIR}/cert/kubernetes/${n}/* ${RPM_WORK_DIR}/SOURCES/certs/${n}/
        tmpnum=$((tmpnum+1))
    done

    # server bin files
    [ -d ${RPM_WORK_DIR}/SOURCES/server/bin ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/server/bin
    cp -a ${WORK_DIR}/bin/{kube-apiserver,kube-controller-manager,kube-scheduler} ${RPM_WORK_DIR}/SOURCES/server/bin/

    # server config files
    [ -d ${RPM_WORK_DIR}/SOURCES/server/etc ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/server/etc
    cp -a ${WORK_DIR}/kubernetes/{kube-apiserver,kube-controller-manager,kube-scheduler} ${RPM_WORK_DIR}/SOURCES/server/etc/

    # server systemd files
    [ -d ${RPM_WORK_DIR}/SOURCES/server/systemd ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/server/systemd
    cp -a ${WORK_DIR}/system/{kube-apiserver.service,kube-controller-manager.service,kube-scheduler.service} ${RPM_WORK_DIR}/SOURCES/server/systemd/

    # client bin files
    [ -d ${RPM_WORK_DIR}/SOURCES/client/bin ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/client/bin
    cp ${WORK_DIR}/bin/{kubelet,kube-proxy} ${RPM_WORK_DIR}/SOURCES/client/bin/

    # client config files
    [ -d ${RPM_WORK_DIR}/SOURCES/client/etc ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/client/etc
    cp -a ${WORK_DIR}/kubernetes/{kubelet,kubelet-config.yaml,kube-proxy,kube-proxy-config.yaml} ${RPM_WORK_DIR}/SOURCES/client/etc/

    # client cert files
    [ -d ${RPM_WORK_DIR}/SOURCES/client/certs ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/client/certs
    cp -a ${WORK_DIR}/cert/kubernetes/kubelet/* ${RPM_WORK_DIR}/SOURCES/client/certs/

    # client systemd files
    [ -d ${RPM_WORK_DIR}/SOURCES/client/systemd ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/client/systemd
    cp -a ${WORK_DIR}/system/{kubelet.service,kube-proxy.service} ${RPM_WORK_DIR}/SOURCES/client/systemd/

    # bin cli files
    [ -d ${RPM_WORK_DIR}/SOURCES/cli ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/cli
    cp ${WORK_DIR}/bin/kubectl ${RPM_WORK_DIR}/SOURCES/cli/

    # etcd cert files
    [ -d ${RPM_WORK_DIR}/SOURCES/etcd ] || mkdir -pv ${RPM_WORK_DIR}/SOURCES/etcd
    cp -a ${WORK_DIR}/cert/etcd/* ${RPM_WORK_DIR}/SOURCES/etcd/

    cat > ${WORK_DIR}/rpmbuild/SPECS/kubernetes.spec << EOF
Name: kubernetes
Version: ${Kubernetes_Version}
Release: 1%{?dist}
Summary: kubernetes
Group: kubernetes
License: GPL

%package log-collection
Summary: kubernetes log collection configurtion file.
Group: Kubernetes/Log
Vendor: Cylon Chau
Source0: kubernetes.conf
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package kubectl
Summary: The commond line interface of kubernetes cluster.
Group: Kubernetes/Cli
Vendor: Cylon Chau
Source1: cli
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package server
Summary: The binary file of kubernetes control plane.
Group: Kubernetes/Server
Vendor:  Cylon Chau
Source2: server
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package admincfg
Summary: The administration configration file of kubernetes cluster.
Group: Kubernetes/Admin
Vendor: Cylon Chau
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client
Summary: The binary file of kubernetes client.
Group: Kubernetes/Client
Vendor: Cylon Chau
Source3: client
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client-certificates
Summary: The certificates of kubernetes client.
Group: Kubernetes/Certificates
Vendor: Cylon Chau
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package etcd-certificates
Summary: The certificates of etcd cluster.
Group:Applications/Certificates
Vendor: Cylon Chau
Source4: etcd
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description
The kubernetes, also known as K8s, is an open source system for managing containerized applications across multiple hosts. It provides basic mechanisms for deployment, maintenance, and scaling of applications.

%description log-collection
The kubernetes rsyslog config

%description kubectl
The Kubernetes Command line tool

%description client-certificates
The certificates of kubernetes client

%description server
The binary, systemd, configuration files of kubernetes control plane

%description client
The binary, systemd, configuration files of kubernetes client

%description admincfg
The administration configration file of kubernetes cluster

%description etcd-certificates
The certificates of etcd cluster.

%define __arch_install_post %{nil}
%define __os_install_post %{nil}
%global debug_package %{nil}

%prep
id kube || useradd kube -s /sbin/nologin -M

%install
rm -rf %{buildroot}
%{__install} -p -D %{SOURCE0} %{buildroot}/etc/rsyslog.d/kubernetes.conf
%{__install} -p -D %{SOURCE1}/kubectl %{buildroot}/usr/local/bin/kubectl

%{__install} -d %{buildroot}/usr/local/bin/
%{__install} -d %{buildroot}${NODE_BIN_DIR}
%{__install} -d %{buildroot}${SERVER_BIN_DIR}
%{__install} -d %{buildroot}/usr/lib/systemd/system/
%{__install} -d  %{buildroot}/etc/kubernetes/

%{__install} -d  %{buildroot}/etc/etcd/

%{__cp} -a %{SOURCE2}/bin/* %{buildroot}${SERVER_BIN_DIR}
%{__cp} -a %{SOURCE2}/etc/* %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE2}/systemd/* %{buildroot}/usr/lib/systemd/system/

%{__cp} -a %{SOURCE3}/bin/* %{buildroot}${NODE_BIN_DIR}
%{__cp} -a %{SOURCE3}/etc/* %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE3}/systemd/* %{buildroot}/usr/lib/systemd/system/

%{__cp} -a %{SOURCE3}/certs/* %{buildroot}/etc/kubernetes/

%{__cp} -a %{SOURCE4}/* %{buildroot}/etc/etcd/

%files log-collection
#%defattr(-,root,root,-)
%attr(0744,root,root) /etc/rsyslog.d/*

%files kubectl
#%defattr(-,root,root,-)
%attr(0755,root,root) /usr/local/bin/kubectl

%files client-certificates
%defattr(-,root,root,-)
%attr(0755,kube,kube) /etc/kubernetes/pki/ca.crt
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-proxy.*
%attr(0755,kube,kube) /etc/kubernetes/auth/*.conf

%files server
%defattr(-,kube,kube,-)
%attr(0755,kube,kube) ${SERVER_BIN_DIR}/kube-apiserver
%attr(0755,kube,kube) ${SERVER_BIN_DIR}/kube-controller-manager
%attr(0755,kube,kube) ${SERVER_BIN_DIR}/kube-scheduler
%attr(0644,kube,kube) /etc/kubernetes/kube-apiserver
%attr(0644,kube,kube) /etc/kubernetes/kube-controller-manager
%attr(0644,kube,kube) /etc/kubernetes/kube-scheduler
%attr(0755,root,root) /usr/lib/systemd/system/kube-apiserver.service
%attr(0755,root,root) /usr/lib/systemd/system/kube-controller-manager.service
%attr(0755,root,root) /usr/lib/systemd/system/kube-scheduler.service

%files client
%defattr(-,root,root,-)
%attr(0755,root,root) ${NODE_BIN_DIR}/kubelet
%attr(0755,root,root) ${NODE_BIN_DIR}/kube-proxy
%attr(0755,root,root) /usr/lib/systemd/system/kube-proxy.service
%attr(0755,root,root) /usr/lib/systemd/system/kubelet.service
%attr(0644,root,root) /etc/kubernetes/kubelet
%attr(0644,root,root) /etc/kubernetes/kubelet-config.yaml
%attr(0644,root,root) /etc/kubernetes/kube-proxy
%attr(0644,root,root) /etc/kubernetes/kube-proxy-config.yaml

# %files admincfg
# %defattr(-,root,root,-)
# %attr(0755,root,root) /etc/kubernetes/auth/admin.conf

%files etcd-certificates
%defattr(-,root,root,-)
%attr(0755,root,root) /etc/etcd/*

%pre server
id kube || useradd kube -s /sbin/nologin -M

%post log-collection
echo -e "\033[32m Don't forget exec [systemctl restart rsyslog]. \033[0m"

%post client
[ -d ${LET_CONF_DIR} ] || mkdir -pv ${LET_CONF_DIR}
echo -e "\033[42;37mDon't forget to modify the kubelet and kube-proxy configuration file.\033[0m"

%postun server
id kube && userdel -r kube

%postun client
echo -e "\033[42;37mAutomatically clean up working directory [${LET_CONF_DIR}].\033[0m"
[ -d ${LET_CONF_DIR} ] || rm -fr ${LET_CONF_DIR}

%changelog log-collection
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package k8s-log-collection

%changelog kubectl
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package kubectl

%changelog client-certificates
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package client-certificates

%changelog server
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package server

%changelog client
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package client

%changelog admincfg
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package admincfg

%changelog etcd-certificates
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package etcd-certificates
EOF
    which rpmbuild &> /dev/null
    if [ $? -ne 0 ];then
        echo -e "\033[41;37mCommond rpmbuild not found.\033[0m"
        exit $CommondNotFound
    fi
    rpmbuild --define "_topdir ${RPM_WORK_DIR}" -ba ${RPM_WORK_DIR}/SPECS/kubernetes.spec

    for n in `ls -tr -I pki -I patches -I ingress -I front-proxy -I kubelet ${WORK_DIR}/cert/kubernetes/`;
    do
        cat > ${WORK_DIR}/rpmbuild/SPECS/kubernetes.spec << EOF
Name: kubernetes
Version: ${Kubernetes_Version}
Release: 1%{?dist}
Summary: kubernetes
Group: kubernetes
License: GPL

%package server-certificates-${n}
Summary: The certificates of kubernetes Server.
Group: Kubernetes/Certificates
Vendor: Cylon Chau
Source0: certs
URL: https://Cylon Chau <cylonchau@outlook.com>
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description
The kubernetes, also known as K8s, is an open source system for managing containerized applications across multiple hosts. It provides basic mechanisms for deployment, maintenance, and scaling of applications.

%description server-certificates-${n}
The certificates of kubernetes control plane

%install
%{__install} -d %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE0}/${n}/* %{buildroot}/etc/kubernetes/

%files server-certificates-${n}
%defattr(-,kube,kube,-)
%attr(0755,kube,kube) /etc/kubernetes/pki/ca.*
%attr(0755,kube,kube) /etc/kubernetes/pki/apiserver-etcd.*
%attr(0755,kube,kube) /etc/kubernetes/pki/apiserver.*
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-controller-manager.*
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-scheduler.*
%attr(0755,kube,kube) /etc/kubernetes/pki/sa.*
%attr(0755,kube,kube) /etc/kubernetes/pki/front-proxy-*
%attr(0755,kube,kube) /etc/kubernetes/auth/controller-manager.conf
%attr(0755,kube,kube) /etc/kubernetes/auth/scheduler.conf
%attr(0755,kube,kube) /etc/kubernetes/token.csv

%pre server-certificates-${n}
id kube || useradd kube -s /sbin/nologin -M

%postun server-certificates-${n}
id kube && userdel -r kube

%changelog server-certificates-${n}
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package server-certificates-${n}
EOF
    rpmbuild --define "_topdir ${RPM_WORK_DIR}" -ba ${RPM_WORK_DIR}/SPECS/kubernetes.spec
    done

    [ -d ${WORK_DIR}/rpms ] || mkdir -pv ${WORK_DIR}/rpms
    cp ${RPM_WORK_DIR}/RPMS/`uname -i`/*.rpm  ${WORK_DIR}/rpms/
    rm -fr ${RPM_WORK_DIR}
}



function build_package(){
    case ${LinuxRelease} in
    "CentOS"|"Redhat")
        read -p "Is it packaged as an RPM? [Y/N default Y]: " ISRPM
        export ISRPM=${ISRPM:-Y}
        if [ ${ISRPM} = "Y" ]; then
            export RPM_WORK_DIR=${WORK_DIR}/rpmbuild
            mkdir -pv ${RPM_WORK_DIR}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
            rpm_logic
        fi
        ;;
    "Debian" | "Ubuntu")
        read -p "Is it packaged as an deb? [Y/N default Y]: " ISDEB
        export ISDEB=${ISDEB:-Y}
        if [ ${ISDEB} = "Y" ]; then

            deb_logic
        fi
        ;;
    *)
        echo -e "\033[41;37munsupport linux release\033[0m"
        ;;
    esac
}

function ensure_linux_release() {
    export LinuxRelease=`awk -F= '/^NAME/{print $2}' /etc/os-release | tr -d '"'|awk '{print $1}'`
}

function clean_work_dir(){
    case ${LinuxRelease} in
    "CentOS"|"Redhat")
        if [ ${ISRPM} == "Y" ];then
            rm -fr ${WORK_DIR}/{kubernetes,rsyslog,system,bin,cert}
            echo -n -e "\n\033[31mPlease install the files under the [${WORK_DIR}/rpms] path directly. \033[0m\n"
        else
            END
        fi
        ;;
    "Debian" | "Ubuntu")
        if [ ${ISDEB} == "Y" ];then
            rm -fr ${WORK_DIR}/{kubernetes,rsyslog,system,bin,cert,DEBIAN}
            echo -n -e "\n\033[31mPlease install the files under the [${WORK_DIR}/debs] path directly. \033[0m\n"
        else
            END
        fi
        ;;
    *)
        echo -e "\033[41;37munsupport linux release\033[0m"
        ;;
    esac

    
}

######################################################################################
#                                   entry function.                                  #
######################################################################################

function MAIN(){
    echo -n -e "generated content\n    1.only certificates for etcd and kubernetes.\n    2.only donwload kubernetes\n    3.certificates and config files.\n"
    read -p "Please enter the which to generate [3]: " INSTALL_OPS
    INSTALL_OPS=${INSTALL_OPS:-3}

    ensure_linux_release
    generate_openssl_config_file

    case ${INSTALL_OPS} in
    1)
        set_env
        download_kube
        extract_kube
        generate_certificates
        clean_bin
        ;;
    2)
        set_env
        download_kube
        extract_kube
        ;;
    3)
        set_env
        download_kube
        extract_kube
        generate_certificates
        action_initial
        build_package
        clean_work_dir
        ;;
    *)
        echo -e "\033[41;37millegal option\033[0m"
        ;;
    esac
}

MAIN
