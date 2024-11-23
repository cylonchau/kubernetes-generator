#!/bin/bash -e

#
# Set Colors
#

bold=$(tput bold)
underline=$(tput sgr 0 1)
reset=$(tput sgr0)

red=$(tput setaf 1)
green=$(tput setaf 76)
white=$(tput setaf 7)
tan=$(tput setaf 202)
blue=$(tput setaf 25)

#
# Headers and Logging
#

underline() { printf "${underline}${bold}%s${reset}\n" "$@"
}
h1() { printf "\n${underline}${bold}${blue}%s${reset}\n" "$@"
}
h2() { printf "\n${underline}${bold}${white}%s${reset}\n" "$@"
}
debug() { printf "${white}%s${reset}\n" "$@"
}
info() { printf "${white}➜ %s${reset}\n" "$@"
}
success() { printf "${green}✔ %s${reset}\n" "$@"
}
error() { printf "${red}✖ %s${reset}\n" "$@"
}
warn() { printf "${tan}➜ %s${reset}\n" "$@"
}
bold() { printf "${bold}%s${reset}\n" "$@"
}
note() { printf "\n${underline}${bold}${blue}Note:${reset} ${blue}%s${reset}\n" "$@"
}

#
# Set env
#

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
KUBEAPISERVER_CLUSTER_IP=
K8S_MASTER_NAME=

[ ca ]
# man ca
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = \${ENV::CERT_DIR}
certs             = \$dir
crl_dir           = \$dir/crl
new_certs_dir     = \$dir
database          = \$dir/index.txt
serial            = \$dir/serial
# certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/intermediate-ca.crl
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
# man req
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

# Certificate extensions (man x509v3_config)

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

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
subjectAltName = @etcd_server_and_peer_dns

[ etcd_peer_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @etcd_server_and_peer_dns

[ etcd_client_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @etcd_client

[ kube_node_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = @kube_node

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
subjectAltName = @master_component_names


[ etcd_server_and_peer_dns ]
DNS.1 = \${ENV::BASE_DOMAIN}
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 127.0.0.5
IP.3 = 10.0.0.3
IP.4 = 10.0.0.4
IP.5 = 10.0.0.5

[ apiserver_names ]
DNS.1 = \${ENV::CLUSTER_NAME}-\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
DNS.3 = kubernetes
DNS.4 = kubernetes.default
DNS.5 = kubernetes.default.svc
DNS.6 = kubernetes.default.svc.cluster.local
IP.1 = \${ENV::KUBEAPISERVER_CLUSTER_IP}
IP.2 = 10.0.0.4
IP.3 = 10.0.0.5
IP.4 = 10.0.0.6


[ master_component_names ]
DNS.1 = \${ENV::K8S_MASTER_NAME}.\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
IP.1 = 127.0.0.1
IP.2 = 10.0.0.4
IP.3 = 10.0.0.5
IP.4 = 10.0.0.6

# used for etcd_client
[ etcd_client ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 10.0.0.5
IP.3 = 10.0.0.4
IP.4 = 10.0.0.6

# used for kubelet kube-proxy
[ kube_node ]
DNS.1 = \${ENV::CLUSTER_NAME}-\${ENV::BASE_DOMAIN}
DNS.2 = \${ENV::BASE_DOMAIN}
IP.1 = \${ENV::KUBEAPISERVER_CLUSTER_IP}
EOF
}

function cert_kubernetes(){
    h2 "Let's configure some parameters below to prepare etcd certificate generation."

    read -p "Pls Enter Kubernetes Domain Name [my-k8s.k8s.io]: " BASE_DOMAIN
    BASE_DOMAIN=${BASE_DOMAIN:-my-k8s.k8s.io}

    read -p "Pls Enter Kubernetes Cluster Name [kubernetes]: " CLUSTER_NAME
    echo -n -e "Enter the IP Address in kubeconfig \n of the Kubernetes API Server IP [10.96.0.1]: "
    read  KUBEAPISERVER_CLUSTER_IP
    read -p "Pls Enter Master servers name [master01 master02]: " MASTERS

    read -p "Pls Enter kubeconfig's server ip [${BASE_DOMAIN}]: " KUBECONFIG_SERVER_IP
    KUBECONFIG_SERVER_IP=${KUBECONFIG_SERVER_IP:-${BASE_DOMAIN}}

    CLUSTER_NAME=${CLUSTER_NAME:-kubernetes}
    KUBEAPISERVER_CLUSTER_IP=${KUBEAPISERVER_CLUSTER_IP:-10.96.0.1}
    MASTERS=${MASTERS:-"master01 master02"}

    read -p "Pls Enter CA Common Name [k8s-ca]: " CERT_CN
    CERT_CN=${CERT_CN:-k8s-ca}

    read -p "Pls Enter k8s cert validity period [3650]: " EXPIRED_DAYS
    EXPIRED_DAYS=${EXPIRED_DAYS:-3650}

    export BASE_DOMAIN CLUSTER_NAME KUBEAPISERVER_CLUSTER_IP MASTERS CERT_CN EXPIRED_DAYS KUBECONFIG_SERVER_IP

    export CA_CERT="$CERT_DIR/ca.crt"
    export CA_KEY="$CERT_DIR/ca.key"
    if [ -f "$CA_CERT" -a -f "$CA_KEY" ]; then
        echo "Using the CA: $CA_CERT and $CA_KEY"
        read -p "pause" A
    else
        echo "Generating CA key and self signed cert."
        openssl genrsa -out $CERT_DIR/ca.key 2048
        openssl req -config openssl.conf \
            -new -x509 -days ${EXPIRED_DAYS} -sha256 \
            -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt \
        -subj "/CN=${CERT_CN}"
    fi
}

function cert_etcd(){
    h2 "Let's configure some parameters below to prepare etcd certificate generation."
    read -p "Pls Enter etcd Domain Name [my-etcd]: " BASE_DOMAIN
    BASE_DOMAIN=${BASE_DOMAIN:-my-etcd}

    read -p "Pls Enter Organization Name [ChinaMobile]: " CERT_O
    CERT_O=${CERT_O:-ChinaMobile}

    read -p "Pls Enter CA Common Name [etcd-ca]: " CERT_CN
    CERT_CN=${CERT_CN:-etcd-ca}

    read -p "Pls Enter etcd cert validity period [3650]: " EXPIRED_DAYS
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
        export CLIENT_CERT_DIR=${KUBELET_DIR}
        ;;
    *)
        export CLIENT_CERT_DIR=${master_dir}
        ;;
    esac
    ${WORK_DIR}/bin/kubectl config set-cluster ${1} \
        --embed-certs=true \
        --server=https://${KUBECONFIG_SERVER_IP}:6443 \
        --certificate-authority=$CA_CERT \
        --kubeconfig=${CLIENT_CERT_DIR}/auth/${3}

    case $2 in
    "system:bootstrapper")
        ${WORK_DIR}/bin/kubectl config set-credentials ${2} \
            --token=${BOOTSTRAP_TOKEN} \
            --kubeconfig=${CLIENT_CERT_DIR}/auth/${3}
        ;;
    *)
        ${WORK_DIR}/bin/kubectl config set-credentials ${2} \
            --embed-certs=true \
            --client-certificate=${CLIENT_CERT_DIR}/pki/${4} \
            --client-key=${CLIENT_CERT_DIR}/pki/${5} \
            --kubeconfig=${CLIENT_CERT_DIR}/auth/${3}
        ;;
    esac

    ${WORK_DIR}/bin/kubectl config set-context ${2}@${1} \
        --user=${2} \
        --cluster=${1} \
        --kubeconfig=${CLIENT_CERT_DIR}/auth/${3}

    ${WORK_DIR}/bin/kubectl config use-context ${2}@${1}  \
        --kubeconfig=${CLIENT_CERT_DIR}/auth/${3}
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

        openssl_sign ${front_proxy_dir}/front-proxy-ca.crt ${front_proxy_dir}/front-proxy-ca.key ${front_proxy_dir} front-proxy-client kube_node_cert
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

        export K8S_MASTER_NAME=${master}

        openssl_req "${master_dir}/pki" kube-apiserver "/CN=kube-apiserver"
        openssl_req "${master_dir}/pki" kube-controller-manager "/CN=system:kube-controller-manager"
        openssl_req "${master_dir}/pki" kube-scheduler "/CN=system:kube-scheduler"
        openssl_req "${master_dir}/pki" apiserver-kubelet-client "/CN=kube-apiserver-kubelet-client/O=system:masters"

        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" kube-apiserver apiserver_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" kube-controller-manager master_component_client_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" kube-scheduler master_component_client_cert
        openssl_sign $CA_CERT $CA_KEY "${master_dir}/pki" apiserver-kubelet-client kube_node_cert
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
        # @1 cluster_name
        # @2 username
        # @3 filename
        # @4 client-ca
        # @5 client-key
        kubeconfig_approve ${CLUSTER_NAME} system:kube-controller-manager kube-controller-manager.conf kube-controller-manager.crt kube-controller-manager.key

        # echo "Generating kubeconfig for kube-scheduler"
        kubeconfig_approve ${CLUSTER_NAME} system:kube-scheduler kube-scheduler.conf kube-scheduler.crt kube-scheduler.key

        # echo "Generating kubeconfig for Cluster Admin"
        kubeconfig_approve ${CLUSTER_NAME} k8s-admin admin.conf apiserver-kubelet-client.crt apiserver-kubelet-client.key
    done

    # Generate key and cert for kubelet
    KUBELET_DIR=${DIR}/kubelet
    mkdir -p ${KUBELET_DIR}/{pki,auth}

    openssl_req ${KUBELET_DIR}/pki kube-proxy "/CN=system:kube-proxy"
    openssl_sign $CA_CERT $CA_KEY ${KUBELET_DIR}/pki kube-proxy kube_node_cert

    rm -f ${KUBELET_DIR}/pki/kube-proxy.csr

    # Copy CA Cert to Node
    cp $CA_CERT ${KUBELET_DIR}/pki/

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
    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR apiserver-etcd etcd_client_cert
    openssl_sign $CERT_DIR/ca.crt $CERT_DIR/ca.key $CERT_DIR client etcd_client_cert

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
function set_kube_version(){
    read -p "Please enter the Kubernetes version to download [1.18.20]: " KUBERNETES_VERSION
    export KUBERNETES_VERSION=${KUBERNETES_VERSION:-1.18.20}

    export BUILD_ARCH=""
    case "`uname -m`" in
    x86* )
        BUILD_ARCH="amd64"
        ;;
    *arm* )
        BUILD_ARCH="arm64"
        ;;
    esac
}

function download_kube(){
    set_kube_version

    export K8S_DOWNLOAD_URL="https://dl.k8s.io/v${KUBERNETES_VERSION}/kubernetes-server-linux-${BUILD_ARCH}.tar.gz"

    # Check if TMP_DIR exists and create if not
    export TMP_DIR=/tmp/${KUBERNETES_VERSION}
    [ ! -d ${TMP_DIR} ] || mkdir -p ${TMP_DIR}
    local kube_file="${TMP_DIR}/kubernetes-server-linux-${BUILD_ARCH}.tar.gz"

    # Check if the Kubernetes file already exists
    if [ -f "$kube_file" ]; then
        warn "Kubernetes v${KUBERNETES_VERSION} already exists. Skipping download."
    else
        # Check if the download URL is valid
        code=$(curl -L -I -w %{http_code} ${K8S_DOWNLOAD_URL} -o /dev/null -s)
        
        case "$code" in
        404)
            warn "Kubernetes version v${KUBERNETES_VERSION} not found."
            exit 1
            ;;
        *)
            note "Download for Kubernetes v${KUBERNETES_VERSION} is begnning."
            wget -t 3 -P ${TMP_DIR} ${K8S_DOWNLOAD_URL}
            if [ $? -ne 0 ]; then
                error "Download failed!"
                exit 1
            fi
            ;;
        esac
    fi
}


function extract_kube(){
    h2 "Unzipping kubernetes bin package."
    export ExtratDir=${TMP_DIR}/kubernetes/server/bin/
    tar xf ${TMP_DIR}/kubernetes-server-linux-amd64.tar.gz -C ${TMP_DIR}/

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
}

function clean_download_dir() {
    set_kube_version
    rm -fr ${TMP_DIR}
}


######################################################################################
#                         initial kubernetes config files.                           #
######################################################################################


function clean_bin(){
    rm -fr ${WORK_DIR}/bin
}

function action_initial(){
    h1 "Let's configure some parameters below to prepare the initial kubernetes config file and systemd file."
    echo -n -e "    1.master.\n    2.node\n    3.all(master and node).\n"
    read -p "Please enter the which to install [3]: " ROLE_PACKAGE
    export ROLE_PACKAGE=${ROLE_PACKAGE:-3}

    case "$ROLE_PACKAGE" in
    1)
        init_kube_server
        init_syslog_conig_file
        ;;
    2)
        init_client
        init_syslog_conig_file
        ;;
    3)
        init_kube_server
        init_client
        init_syslog_conig_file
        ;;
    *)
        error "millegal content \"${ROLE_PACKAGE}\""
        exit $IllegalContent
        ;;
    esac
}

function init_kube_server(){
    h1 "Generating k8s master configuration is beginning..."
    read -p "Please enter the binary file path of server [/usr/local/bin]: " KUBE_SERVER_BIN_DIR
    export KUBE_SERVER_BIN_DIR=${KUBE_SERVER_BIN_DIR:-/usr/local/bin}
    init_kube_apiserver
    init_kube_controller_manager
    init_kube_scheduler
}

######################################################################################
#                  initial kubernetes server config files.                           #
######################################################################################


function init_kube_apiserver(){
    h2 "Let's configure some parameters below to prepare to generate the kube-apiserver config file."

    read -p "Please enter the \"kube-apiserver\" service name [kube-apiserver]: " KUBE_APISERVER_NAME
    export KUBE_APISERVER_NAME=${KUBE_APISERVER_NAME:-kube-apiserver}

    read -p "Please enter cluster IP range [10.96.0.0/22]: " SVC_IP_RANGE
    export SVC_IP_RANGE=${SVC_IP_RANGE:-10.96.0.0/22}

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

    cat > ${CONF_DIR}/${KUBE_APISERVER_NAME} << EOF
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
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=${SVC_IP_RANGE}"

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
    --tls-cert-file=${CA_PATH}/kube-apiserver.crt \\
    --tls-private-key-file=${CA_PATH}/kube-apiserver.key \\
    --token-auth-file=${TOKEN_PATH}/token.csv"
EOF
    cat > ${SYSTEMD_DIR}/${KUBE_APISERVER_NAME}.service << EOF
[Unit]
Description=Kubernetes kube-apiserver service
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${KUBE_APISERVER_NAME}
User=kube
ExecStart=${KUBE_SERVER_BIN_DIR}/${KUBE_APISERVER_NAME} \\
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
SyslogIdentifier=${KUBE_APISERVER_NAME}
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
}

function init_kube_controller_manager(){
    h2 "Let's configure some parameters below to prepare to generate the \"kube-controller-manager\" config file."

    read -p "Please enter cluster IP cidr [10.244.0.0/16]: " CM_CLUSTER_CIDR
    export CM_CLUSTER_CIDR=${CM_CLUSTER_CIDR:-10.244.0.0/16}

    read -p "Please enter the \"kube-controller-manager\" service name [kube-controller-manager]: " KUBE_CONTROLLER_MANAGER_NAME
    export KUBE_CONTROLLER_MANAGER_NAME=${KUBE_CONTROLLER_MANAGER_NAME:-kube-controller-manager}

    cat > ${CONF_DIR}/${KUBE_CONTROLLER_MANAGER_NAME} << EOF
# The following values are used to configure the kubernetes controller-manager
#
# defaults from config and apiserver should be adequate

# You can add your configurion own!
KUBE_CONTROLLER_MANAGER_ARGS="--v=0 \\
    --logtostderr=true \\
    --allocate-node-cidrs=true \\
    --authentication-kubeconfig=/etc/kubernetes/auth/kube-controller-manager.conf \\
    --authorization-kubeconfig=/etc/kubernetes/auth/kube-controller-manager.conf \\
    --client-ca-file=${CA_PATH}/ca.crt \\
    --root-ca-file=${CA_PATH}/ca.crt \\
    --cluster-cidr=${CM_CLUSTER_CIDR} \\
    --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt \\
    --cluster-signing-key-file=/etc/kubernetes/pki/ca.key \\
    --controllers=*,bootstrapsigner,tokencleaner \\
    --kubeconfig=/etc/kubernetes/auth/kube-controller-manager.conf \\
    --leader-elect=true \\
    --node-cidr-mask-size=24 \\
    --requestheader-client-ca-file=${CA_PATH}/front-proxy-ca.crt \\
    --service-account-private-key-file=/etc/kubernetes/pki/sa.key \\
    --use-service-account-credentials=true"
EOF

    cat > ${SYSTEMD_DIR}/${KUBE_CONTROLLER_MANAGER_NAME}.service << EOF
[Unit]
Description=Kubernetes kube-controller-manager service
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${KUBE_CONTROLLER_MANAGER_NAME}
User=kube
ExecStart=${KUBE_SERVER_BIN_DIR}/${KUBE_CONTROLLER_MANAGER_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${KUBE_CONTROLLER_MANAGER_NAME}
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
}


function init_kube_scheduler(){
   h2 "Let's configure some parameters below to prepare to generate the \"kube-scheduler\" config file."

    read -p "Please enter the \"kube-scheduler\" service name [kube-scheduler]: " KUBE_SCHEDR_NAME
    export KUBE_SCHEDR_NAME=${KUBE_SCHEDR_NAME:-kube-scheduler}

    cat > ${CONF_DIR}/${KUBE_SCHEDR_NAME} << EOF
# kubernetes scheduler config
#
# default config should be adequate
#
# You can add your configurtion own!
KUBE_SCHEDULER_ARGS="--v=0 \\
    --logtostderr=true \\
    --kubeconfig=/etc/kubernetes/auth/kube-scheduler.conf"
EOF

    cat > ${SYSTEMD_DIR}/${KUBE_SCHEDR_NAME}.service << EOF
[Unit]
Description=Kubernetes kube-scheduler service
Documentation=https://github.com/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/${KUBE_SCHEDR_NAME}
User=kube
ExecStart=${KUBE_SERVER_BIN_DIR}/${KUBE_SCHEDR_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${KUBE_SCHEDR_NAME}
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
}


######################################################################################
#                    initial kubernetes node config files.                           #
######################################################################################


function init_client(){
    h1 "Generating k8s node configuration is beginning..."
    
    read -p "Please enter the binary file path of node [/usr/local/bin]: " KUBE_WORKER_BIN_DIR
    export KUBE_WORKER_BIN_DIR=${KUBE_WORKER_BIN_DIR:-/usr/local/bin}
    init_kubelet
    init_proxy
}

function init_kubelet(){
    h2 "Let's configure some parameters below to prepare to generate the kubelet config file."

    read -p "Please enter the \"kubelet\" service name [kubelet]: " KUBELET_NAME
    export KUBELET_NAME=${KUBELET_NAME:-kubelet}

    read -p "Please enter the \"kubelet\" working directory [/var/lib/kubelet]: " LET_CONF_DIR
    export LET_CONF_DIR=${LET_CONF_DIR:-/var/lib/kubelet}

    # read -p "Please enter kubeconfig path for the kubelet [/etc/kubernetes/auth]: " LET_KUBECONF_DIR
    # export LET_KUBECONF_DIR=${LET_KUBECONF_DIR:-/etc/kubernetes/auth}

    cat > ${CONF_DIR}/${KUBELET_NAME} << EOF
# kubernetes kubelet config
#
# You can add your configuration own!
KUBELET_ARGS="--v=0 \\
    --logtostderr=true \\
    --network-plugin=cni \\
    --config=/etc/kubernetes/${KUBELET_NAME}-config.yaml \\
    --kubeconfig=/etc/kubernetes/auth/${KUBELET_NAME}.conf \\
    --bootstrap-kubeconfig=/etc/kubernetes/auth/bootstrap.conf"
EOF
    ${WORK_DIR}/bin/kubeadm config print init-defaults --component-configs KubeletConfiguration|grep -A 1000 'apiVersion: kubelet.config.k8s.io/v1beta1' > ${CONF_DIR}/${KUBELET_NAME}-config.yaml
    sed -i 's@0s@20s@g' ${CONF_DIR}/${KUBELET_NAME}-config.yaml

    cat > ${SYSTEMD_DIR}/${KUBELET_NAME}.service << EOF
[Unit]
Description=Kubernetes kubelet service
Documentation=https://github.com/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=${LET_CONF_DIR}
EnvironmentFile=-/etc/kubernetes/${KUBELET_NAME}
ExecStart=${KUBE_WORKER_BIN_DIR}/${KUBELET_NAME} \\
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
SyslogIdentifier=${KUBELET_NAME}
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
}

function init_proxy(){
    h2 "Let's configure some parameters below to prepare to generate the kube-proxy config file."
    read -p "Please enter the \"kube-proxy\" service name [kube-proxy]: " KUBE_PROXY_NAME
    export KUBE_PROXY_NAME=${KUBE_PROXY_NAME:-kube-proxy}

    cat > ${CONF_DIR}/${KUBE_PROXY_NAME} << EOF
# kubernetes proxy config
#
# You can add your configuration own!
KUBE_PROXY_ARGS="--v=0 \\
    --logtostderr=true \\
    --config=/etc/kubernetes/${KUBE_PROXY_NAME}-config.yaml"
EOF
    ${WORK_DIR}/bin/kubeadm config print init-defaults --component-configs KubeProxyConfiguration|grep -A 1000 'kubeproxy.config.k8s.io/v1alpha1' > ${CONF_DIR}/${KUBE_PROXY_NAME}-config.yaml
    sed -i "s@kubeconfig: /var/lib/kube-proxy/kubeconfig.conf@kubeconfig: /etc/kubernetes/${KUBE_PROXY_NAME}.conf@g" ${CONF_DIR}/${KUBE_PROXY_NAME}-config.yaml
    sed -i "s@clusterCIDR: \"\"@clusterCIDR: \"${CM_CLUSTER_CIDR}\"@g" ${CONF_DIR}/${KUBE_PROXY_NAME}-config.yaml

    cat > ${SYSTEMD_DIR}/${KUBE_PROXY_NAME}.service << EOF
[Unit]
Description=Kubernetes kube-proxy service
Documentation=https://github.com/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/${KUBE_PROXY_NAME}
ExecStart=${KUBE_WORKER_BIN_DIR}/${KUBE_PROXY_NAME} \\
    \$KUBE_MASTER \\
    \$KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536
KillSignal=SIGTERM
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=${KUBE_PROXY_NAME}
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF
}



######################################################################################
#                  initial rsyslog config files of kubernetes.                       #
######################################################################################


function init_syslog_conig_file(){
    cat > ${LOG_CONFIG_DIR}/kubernetes.conf << EOF
if (\$programname == '${KUBE_APISERVER_NAME}') then {
   action(type="omfile" file="/var/log/apiserver.log")
   stop
} else if (\$programname == '${KUBE_SCHEDR_NAME}') then {
   action(type="omfile" file="/var/log/scheduler.log")
   stop
} else if (\$programname == '${KUBE_CONTROLLER_MANAGER_NAME}') then {
   action(type="omfile" file="/var/log/controller-manager.log")
   stop
} else if (\$programname == '${KUBELET_NAME}') then {
   action(type="omfile" file="/var/log/kubelet.log")
   stop
} else if (\$programname == '${KUBE_PROXY_NAME}') then {
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
    note "The certificate files is in ${WORK_DIR}/cert/."
    note "Please copy the ${CONF_DIR} to /etc/."
    note "Please copy the ${SYSTEMD_DIR} to /usr/lib/systemd/."
    note "Please modify the kube-proxy config file ${CONF_DIR}/${KUBE_PROXY_NAME}-config.yaml
        and kubelet config file ${CONF_DIR}/${KUBELET_NAME}-config.yaml as required."
    note "Please copy the ${LOG_CONFIG_DIR} to /etc/.
        Don't forget restart service rsyslog."
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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
Description: kubernetes-server is you kubernetes server, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/preinst << EOF
#!/bin/bash
id kube || useradd kube -s /sbin/nologin -M
EOF

    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/postinst << EOF
#!/bin/bash
chown kube:kube -R ${LINUX_CONFIG_DIR}
chmod 555 ${KUBE_SERVER_BIN_DIR}/{kube-apiserver,kube-controller-manager,kube-scheduler}
EOF

    chmod +x ${KUBE_NODE_BUILD_DIR}/DEBIAN/{preinst,postinst}
    # server bin files
    DEB_KUBE_SERVER_BIN_DIR=${KUBE_SERVER_BUILD_DIR}/${KUBE_SERVER_BIN_DIR}
    install -d ${DEB_KUBE_SERVER_BIN_DIR}
    cp -a ${WORK_DIR}/bin/{kube-apiserver,kube-controller-manager,kube-scheduler} ${DEB_KUBE_SERVER_BIN_DIR}

    # server config files
    LINUX_CONFIG_DIR=/etc/kubernetes/
    DEB_SERVER_CONFIG_DIR=${KUBE_SERVER_BUILD_DIR}${LINUX_CONFIG_DIR}
    install -d ${DEB_SERVER_CONFIG_DIR}
    cp -a ${WORK_DIR}/kubernetes/{kube-apiserver,kube-controller-manager,kube-scheduler} ${DEB_SERVER_CONFIG_DIR}

    # server systemd files
    DEB_SERVER_SYSTEMD_DIR=${KUBE_SERVER_BUILD_DIR}/lib/systemd/system/
    install -d ${DEB_SERVER_SYSTEMD_DIR}
    cp -a ${WORK_DIR}/system/{kube-apiserver.service,kube-controller-manager.service,kube-scheduler.service} ${DEB_SERVER_SYSTEMD_DIR}


    ############################################################
    # install kubernetes worker components to build root dir   #
    ############################################################
    export KUBE_NODE_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-node
    install -d ${KUBE_NODE_BUILD_DIR}/DEBIAN
    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-node
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
Description: kubernetes-node is your kubernetes node component, generated with cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF

    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/preinst << EOF
#!/bin/bash
id kube || useradd kube -s /sbin/nologin -M
EOF

    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/postinst << EOF
#!/bin/bash
chown root:root -R ${LINUX_CONFIG_DIR}
chmod 555 ${KUBE_SERVER_BIN_DIR}/{kubelet,kube-proxy}
chown kube:kube /var/lib/kubelet
EOF

    chmod +x ${KUBE_NODE_BUILD_DIR}/DEBIAN/{preinst,postinst}
    # worker bin files
    DEB_WORKER_BIN_DIR=${KUBE_NODE_BUILD_DIR}/${KUBE_WORKER_BIN_DIR}
    install -d ${DEB_WORKER_BIN_DIR}
    cp -a ${WORK_DIR}/bin/{kubelet,kube-proxy} ${DEB_WORKER_BIN_DIR}

    # worker config files
    DEB_WORKER_CONFIG_DIR=${KUBE_NODE_BUILD_DIR}/etc/kubernetes
    install -d ${DEB_WORKER_CONFIG_DIR}
    cp -a ${WORK_DIR}/kubernetes/{kubelet,kubelet-config.yaml,kube-proxy,kube-proxy-config.yaml} ${DEB_WORKER_CONFIG_DIR}

    # worker systemd files
    DEB_WORKER_SYSTEMD_DIR=${KUBE_NODE_BUILD_DIR}/lib/systemd/system/
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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
Description: kubernetes-server-certificates is your kubernetes control plane components certs, generated using cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
        cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/preinst << EOF
#!/bin/bash
id kube || useradd kube -s /sbin/nologin -M
EOF

        cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/postinst << EOF
#!/bin/bash
chown kube:kube -R /etc/kubernetes
EOF

        chmod +x ${KUBE_NODE_BUILD_DIR}/DEBIAN/{preinst,postinst}

        DEB_SERVER_CERT_DIR=${KUBE_SERVER_CERT_BUILD_DIR}/${TOKEN_PATH}
        install -d ${DEB_SERVER_CERT_DIR}
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/pki ${KUBE_SERVER_CERT_BUILD_DIR}/${CA_PATH}
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/token.csv ${DEB_SERVER_CERT_DIR}/

        install -d ${DEB_SERVER_CERT_DIR}/auth
        cp -a ${WORK_DIR}/cert/kubernetes/${master}/auth/{kube-controller-manager.conf,kube-scheduler.conf} ${DEB_SERVER_CERT_DIR}/auth/
    

        #############################################################
        #  install kubernetes kubernetes-admincfg to build root dir #
        #############################################################

        export KUBE_ADMINCFG_BUILD_DIR=${DEB_WORK_DIR}/kubernetes-admincfg-${master}
        install -d ${KUBE_ADMINCFG_BUILD_DIR}/DEBIAN
        cat > ${KUBE_ADMINCFG_BUILD_DIR}/DEBIAN/control << EOF
Package: kubernetes-admincfg-${master}
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
Description: kubernetes-node-certificates is your kubernetes worker components certs, generated using cylonchau's kubernetes-generator
Maintainer: Cylon Chau <cylonchau@outlook.com>
Section: comm
Homepage: https://kubernetes.io
EOF
    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/preinst << EOF
#!/bin/bash
id kube || useradd kube -s /sbin/nologin -M
EOF

    cat > ${KUBE_NODE_BUILD_DIR}/DEBIAN/postinst << EOF
#!/bin/bash
chown kube:kube -R /etc/kubernetes
EOF

    chmod +x ${KUBE_NODE_BUILD_DIR}/DEBIAN/{preinst,postinst}

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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
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
Version: ${KUBERNETES_VERSION}
Architecture: ${BUILD_ARCH}
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
Version: ${KUBERNETES_VERSION}
Release: 1%{?dist}
Summary: kubernetes
Group: kubernetes
License: GPL

%package log-collection
Summary: kubernetes log collection configurtion file.
Group: Kubernetes/Log
Vendor: Cylon Chau
Source0: kubernetes.conf
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package kubectl
Summary: The commond line interface of kubernetes cluster.
Group: Kubernetes/Cli
Vendor: Cylon Chau
Source1: cli
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package server
Summary: The binary file of kubernetes control plane.
Group: Kubernetes/Server
Vendor:  Cylon Chau
Source2: server
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client
Summary: The binary file of kubernetes client.
Group: Kubernetes/Client
Vendor: Cylon Chau
Source3: client
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client-certificates
Summary: The certificates of kubernetes client.
Group: Kubernetes/Certificates
Vendor: Cylon Chau
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package etcd-certificates
Summary: The certificates of etcd cluster.
Group:Applications/Certificates
Vendor: Cylon Chau
Source4: etcd
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package kube-apiserver-etcd-certificates
Summary: The certificates of etcd cluster.
Group: Kubernetes/etcd-client-Certificates
Vendor: Cylon Chau
Source5: etcd
URL: https://cylonchau.github.io
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

%description etcd-certificates
The certificates of etcd cluster.

%description kube-apiserver-etcd-certificates
The certificates of kube-apiserver connect to etcd cluster.

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
%{__install} -d %{buildroot}${KUBE_WORKER_BIN_DIR}
%{__install} -d %{buildroot}${KUBE_SERVER_BIN_DIR}
%{__install} -d %{buildroot}/usr/lib/systemd/system/
%{__install} -d  %{buildroot}/etc/kubernetes/

%{__install} -d  %{buildroot}/etc/etcd/

%{__cp} -a %{SOURCE2}/bin/* %{buildroot}${KUBE_SERVER_BIN_DIR}
%{__cp} -a %{SOURCE2}/etc/* %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE2}/systemd/* %{buildroot}/usr/lib/systemd/system/

%{__cp} -a %{SOURCE3}/bin/* %{buildroot}${KUBE_WORKER_BIN_DIR}
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
%attr(0755,kube,kube) ${KUBE_SERVER_BIN_DIR}/kube-apiserver
%attr(0755,kube,kube) ${KUBE_SERVER_BIN_DIR}/kube-controller-manager
%attr(0755,kube,kube) ${KUBE_SERVER_BIN_DIR}/kube-scheduler
%attr(0644,kube,kube) /etc/kubernetes/kube-apiserver
%attr(0644,kube,kube) /etc/kubernetes/kube-controller-manager
%attr(0644,kube,kube) /etc/kubernetes/kube-scheduler
%attr(0755,root,root) /usr/lib/systemd/system/kube-apiserver.service
%attr(0755,root,root) /usr/lib/systemd/system/kube-controller-manager.service
%attr(0755,root,root) /usr/lib/systemd/system/kube-scheduler.service

%files client
%defattr(-,root,root,-)
%attr(0755,root,root) ${KUBE_WORKER_BIN_DIR}/kubelet
%attr(0755,root,root) ${KUBE_WORKER_BIN_DIR}/kube-proxy
%attr(0755,root,root) /usr/lib/systemd/system/kube-proxy.service
%attr(0755,root,root) /usr/lib/systemd/system/kubelet.service
%attr(0644,root,root) /etc/kubernetes/kubelet
%attr(0644,root,root) /etc/kubernetes/kubelet-config.yaml
%attr(0644,root,root) /etc/kubernetes/kube-proxy
%attr(0644,root,root) /etc/kubernetes/kube-proxy-config.yaml

%files etcd-certificates
%defattr(-,root,root,-)
%attr(0755,root,root) /etc/etcd/pki/ca.*
%attr(0755,root,root) /etc/etcd/pki/client.*
%attr(0755,root,root) /etc/etcd/pki/peer.*
%attr(0755,root,root) /etc/etcd/pki/server.*

%files kube-apiserver-etcd-certificates
%defattr(-,root,root,-)
%attr(0755,root,root) /etc/etcd/pki/apiserver-etcd.*

%pre server
id kube || useradd kube -s /sbin/nologin -M

%post log-collection
echo -e "\033[32m Don't forget exec [systemctl restart rsyslog]. \033[0m"

%post client
[ -d ${LET_CONF_DIR} ] || mkdir -pv ${LET_CONF_DIR}
echo -e "\033[42;37mDon't forget to modify the kubelet and kube-proxy configuration file.\033[0m"

%postun server
id kube &> /dev/null && userdel -r kube

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
    which rpmbuild &> /dev/null || sudo yum install -y rpm-build redhat-rpm-config rpmdevtools
    rpmbuild --define "_topdir ${RPM_WORK_DIR}" --define="%_unpackaged_files_terminate_build 0" -ba ${RPM_WORK_DIR}/SPECS/kubernetes.spec

    for n in `ls -tr -I pki -I patches -I ingress -I front-proxy -I kubelet ${WORK_DIR}/cert/kubernetes/`;
    do
        cat > ${WORK_DIR}/rpmbuild/SPECS/kubernetes.spec << EOF
Name: kubernetes
Version: ${KUBERNETES_VERSION}
Release: 1%{?dist}
Summary: kubernetes
Group: kubernetes
License: GPL

%package server-certificates-${n}
Summary: The certificates of kubernetes Server.
Group: Kubernetes/Certificates
Vendor: Cylon Chau
Source0: certs
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package admincfg-${n}
Summary: The administration configration file of kubernetes cluster.
Group: Kubernetes/Admin
Vendor: Cylon Chau
URL: https://cylonchau.github.io
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%description
The kubernetes, also known as K8s, is an open source system for managing containerized applications across multiple hosts. It provides basic mechanisms for deployment, maintenance, and scaling of applications.

%description server-certificates-${n}
The certificates of kubernetes control plane

%description admincfg-${n}
The administration configration file of kubernetes cluster

%install
%{__install} -d %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE0}/${n}/* %{buildroot}/etc/kubernetes/

%files server-certificates-${n}
%defattr(-,kube,kube,-)
%attr(0755,kube,kube) /etc/kubernetes/pki/ca.*
%attr(0755,kube,kube) /etc/kubernetes/pki/apiserver-etcd.*
%attr(0755,kube,kube) /etc/kubernetes/pki/apiserver-kubelet-client.*
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-apiserver.*
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-controller-manager.*
%attr(0755,kube,kube) /etc/kubernetes/pki/kube-scheduler.*
%attr(0755,kube,kube) /etc/kubernetes/pki/sa.*
%attr(0755,kube,kube) /etc/kubernetes/pki/front-proxy-*
%attr(0755,kube,kube) /etc/kubernetes/auth/kube-controller-manager.conf
%attr(0755,kube,kube) /etc/kubernetes/auth/scheduler.conf
%attr(0755,kube,kube) /etc/kubernetes/token.csv

%files admincfg-${n}
%defattr(-,kube,kube,-)
%attr(0755,kube,kube) /etc/kubernetes/auth/admin.conf

%pre server-certificates-${n}
id kube || useradd kube -s /sbin/nologin -M

%postun server-certificates-${n}
id kube &> /dev/null && userdel -r kube

%changelog server-certificates-${n}
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package server-certificates-${n}

%changelog admincfg-${n}
* $(date +"%a %b %d %Y") $(id|awk -F '(' '{print $2}'|awk -F ')' '{print $1}')
- package admincfg-${n}
EOF
    rpmbuild --define "_topdir ${RPM_WORK_DIR}" --define="%_unpackaged_files_terminate_build 0" -ba ${RPM_WORK_DIR}/SPECS/kubernetes.spec
    done

    [ -d ${WORK_DIR}/rpms ] || mkdir -pv ${WORK_DIR}/rpms
    cp ${RPM_WORK_DIR}/RPMS/`uname -i`/*.rpm  ${WORK_DIR}/rpms/
    rm -fr ${RPM_WORK_DIR}
}



function build_package(){
    h1 "Generating linux package is beginning..."
    case ${LinuxRelease} in
    "CentOS"|"Redhat")
        read -p "Is it packaged as an RPM? [Y/N default Y]: " ISRPM
        export ISRPM=${ISRPM:-Y}
        if [ ${ISRPM} = "Y" ]; then
            note "You selected make (.rpm) package."
            export RPM_WORK_DIR=${WORK_DIR}/rpmbuild
            mkdir -pv ${RPM_WORK_DIR}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
            rpm_logic
        else
            bold "You don't have select make (.rpm) package."
        fi
        ;;
    "Debian" | "Ubuntu")
        read -p "Is it packaged as an deb? [Y/N default Y]: " ISDEB
        export ISDEB=${ISDEB:-Y}
        if [ ${ISDEB} = "Y" ]; then
            note "You selected make (.deb) package."
            deb_logic
        else
            bold "You don't have select make (.deb) package."
        fi
        ;;
    *)
        error "Unsupport linux release"
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
            note "Please install the files under the [${WORK_DIR}/rpms] path directly. "
        else
            END
        fi
        ;;
    "Debian" | "Ubuntu")
        if [ ${ISDEB} == "Y" ];then
            rm -fr ${WORK_DIR}/{kubernetes,rsyslog,system,bin,cert,DEBIAN}
            note "Please install the files under the [${WORK_DIR}/debs] path directly."
        else
            END
        fi
        ;;
    *)
        note "Unsupport linux release"
        ;;
    esac

    
}

######################################################################################
#                                   entry function.                                  #
######################################################################################

function MAIN(){
    echo -n -e "generated content\n    1.only certificates for etcd and kubernetes.\n    2.only donwload kubernetes\n    3.certificates and config files.\n    4.clean download file.\n"
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
    4)
        clean_download_dir
        ;;
    *)
        error "illegal option"
        ;;
    esac
}

MAIN