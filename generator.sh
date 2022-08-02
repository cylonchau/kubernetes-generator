#!/bin/bash -e

set -e
NotFount=204
IllegalContent=205
CommondNotFound=127

ROOT=$(cd $(dirname $0); pwd)
export ROOT

function cert_kubernetes(){
    echo -n -e "\n\033[41;37mLet's configure some parameters below to prepare etcd certificate generation.\033[0m\n\n" 
    read -p "Pls Enter Kubernetes Domain Name [my-k8s.k8s.io]: " BASE_DOMAIN
    BASE_DOMAIN=${BASE_DOMAIN:-my-k8s.k8s.io}

    read -p "Pls Enter Kubernetes Cluster Name [kubernetes]: " CLUSTER_NAME
    echo -n -e "Enter the IP Address in kubeconfig \n of the Kubernetes API Server IP [10.96.0.1]: "
    read  APISERVER_CLUSTER_IP
    read -p "Pls Enter Master servers name [master01 master02 master03]: " MASTERS
    
    read -p "Pls Enter kubeconfig's server ip [${BASE_DOMAIN}]: " KUBECONFIG_SERVER_IP
    KUBECONFIG_SERVER_IP=${KUBECONFIG_SERVER_IP:-${BASE_DOMAIN}}

    CLUSTER_NAME=${CLUSTER_NAME:-kubernetes}
    APISERVER_CLUSTER_IP=${APISERVER_CLUSTER_IP:-10.96.0.1}
    MASTERS=${MASTERS:-"master01 master02 master03"}

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

function Generate_Certificates(){
    set_cert_evn etcd
    cert_etcd
    generate_etcd_certificates
    set_cert_evn kubernetes
    cert_kubernetes
    generate_kubernetes_certificates
}



function DownloadKube(){
    read -p "Please enter the kubernetes version to download [1.18.20]: " Kubernetes_Version
    export Kubernetes_Version=${Kubernetes_Version:-1.18.20}

    arch=""
    case "`uname -m`" in
    x86*)
        arch="amd64"
        ;;
    *arm*)
        arch="arm64"
        ;;

    esac
    
    export KubernetesDownloadUrl="https://dl.k8s.io/v${Kubernetes_Version}/kubernetes-server-linux-${arch}.tar.gz"
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

function ExtractKube(){
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

function CleanBin(){
    rm -fr ${WORK_DIR}/bin
}

function ActionInitail(){
    echo -n -e "\n\033[41;37mLet's configure some parameters below to prepare the initial kubernetes config file and systemd file. \033[0m\n" 
    
    echo -n -e "    1.master.\n    2.node\n    3.all(master and node).\n"
    read -p "Please enter the which to install [3]: " ROLE_PACKAGE
    export ROLE_PACKAGE=${ROLE_PACKAGE:-3}

    case "$ROLE_PACKAGE" in
    1)
        INIT_SERVER
        InitRsyslogConigFile
        ;;
    2)
        INIT_CLIENT
        InitRsyslogConigFile
        ;;
    3)
        INIT_SERVER
        INIT_CLIENT
        InitRsyslogConigFile
        ;;
    *)  
        echo -e "\033[41;37millegal content \"${ROLE_PACKAGE}\".\033[0m" 
        exit $IllegalContent
        ;;
    esac   
}

function INIT_SERVER(){
    echo -e "\n"
    read -p "Please enter the binary file path of server [/usr/local/bin]: " SERVER_BIN_DIR
    export SERVER_BIN_DIR=${SERVER_BIN_DIR:-/usr/local/bin}
    InitAPIServer
    InitControllerManager
    InitScheduler
}

function InitAPIServer(){
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

function InitControllerManager(){
    echo -n -e "\nLet's configure some parameters below to prepare to 
        generate the \033[41;37mkube-controller-manager\033[0m config file.\n\n" 
    read -p "Please enter kube-controller-manager listen addr [127.0.0.1]: " CM_LISTEN
    export CM_LISTEN=${CM_LISTEN:-127.0.0.1}

    read -p "Please enter cluster IP cidr [10.244.0.0/16]: " CM_CIDR
    export CM_CIDR=${CM_CIDR:-10.244.0.0/16}
    
    read -p "Please enter cluster cetaficate file path [/etc/kubernetes/pki]: " CA_PATH
    export CA_PATH=${CA_PATH:-/etc/kubernetes/pki}

    read -p "Please enter the \"kube-controller-manager\" service name [kube-controller-manager]: " CONTRO_NAME
    export CONTRO_NAME=${CONTRO_NAME:-kube-controller-manager}

    cat > ${CONF_DIR}/${CONTRO_NAME} << EOF
# The following values are used to configure the kubernetes controller-manager
#
# defaults from config and apiserver should be adequate

# You can add your configurion own!
KUBE_CONTROLLER_MANAGER_ARGS="--v=0 \\
    --logtostderr=true \\
    --bind-address=${CM_LISTEN} \\
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


function InitScheduler(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkube-scheduler\033[0m config file.\n\n" 

    read -p "Please enter the \"kube-scheduler\" service name [kube-scheduler]: " SCHEDR_NAME
    export SCHEDR_NAME=${SCHEDR_NAME:-kube-scheduler}

    read -p "Please enter kube-scheduler listen addr [127.0.0.1]: " SCHED_LISTEN
    export SCHED_LISTEN=${SCHED_LISTEN:-127.0.0.1}
    
    cat > ${CONF_DIR}/${SCHEDR_NAME} << EOF
# kubernetes scheduler config
#
# default config should be adequate
#
# You can add your configurtion own!
KUBE_SCHEDULER_ARGS="--v=0 \\
    --logtostderr=true \\
    --address=${SCHED_LISTEN} \\
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

function INIT_CLIENT(){
    echo -e "\n"
    read -p "Please enter the binary file path of client [/usr/local/bin]: " CLIENT_BIN_DIR
    export CLIENT_BIN_DIR=${CLIENT_BIN_DIR:-/usr/local/bin}
    InitKubelet
    InitProxy
}

function InitKubelet(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkubelet\033[0m config file.\n\n" 
    
    read -p "Please enter the \"kubelet\" service name [kubelet]: " LET_NAME
    export LET_NAME=${LET_NAME:-kubelet}

    read -p "Please enter kubelet listen addr [0.0.0.0]: " LET_LISTEN
    export LET_LISTEN=${LET_LISTEN:-0.0.0.0}

    read -p "Please enter port for the kubelet [10250]: " LET_PORT
    export LET_PORT=${LET_PORT:-10250}

    read -p "Please enter kubeconfig path for the kubelet [/etc/kubernetes/auth]: " LET_KUBECONF_DIR
    export LET_KUBECONF_DIR=${LET_KUBECONF_DIR:-/etc/kubernetes/auth}

    cat > ${CONF_DIR}/${LET_NAME} << EOF
# kubernetes kubelet config
#
# The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
KUBELET_ADDRESS="--address=${LET_LISTEN}"

# The port for the info server to serve on
# KUBELET_PORT="--port=${LET_PORT}"

# You can add your configuration own!
KUBELET_ARGS="--v=0 \\
    --logtostderr=true \\
    --network-plugin=cni \\
    --config=/etc/kubernetes/${LET_NAME}-config.yaml \\
    --kubeconfig=${LET_KUBECONF_DIR}/${LET_NAME}.conf \\
    --bootstrap-kubeconfig=${LET_KUBECONF_DIR}/bootstrap.conf"
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
User=kube
WorkingDirectory=${LET_CONF_DIR}
EnvironmentFile=-/etc/kubernetes/${LET_NAME}
ExecStart=${CLIENT_BIN_DIR}/${LET_NAME} \\
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

function InitProxy(){
    echo -n -e "\nLet's configure some parameters below to prepare to
        generate the \033[41;37mkube-proxy\033[0m config file.\n\n" 
    read -p "Please enter the \"kube-proxy\" service name [kube-proxy]: " PROXY_NAME
    export PROXY_NAME=${PROXY_NAME:-kube-proxy}

    read -p "Please enter kube-proxy listen addr [0.0.0.0]: " PROXY_LISTEN
    export PROXY_LISTEN=${PROXY_LISTEN:-0.0.0.0}

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
User=kube
EnvironmentFile=-/etc/kubernetes/${PROXY_NAME} 
ExecStart=${CLIENT_BIN_DIR}/${PROXY_NAME} \\
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

function InitRsyslogConigFile(){
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

function RPM(){
    read -p "Is it packaged as an RPM? [Y/N default Y]: " ISRPM
    export ISRPM=${ISRPM:-Y}
    if [ ${ISRPM} = "Y" ]; then
        export RPM_WORK_DIR=${WORK_DIR}/rpmbuild
        mkdir -pv ${RPM_WORK_DIR}/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
        RPM_LOGIC
    fi
}

function RPM_LOGIC(){
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
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package kubectl
Summary: The commond line interface of kubernetes cluster.
Group: Kubernetes/Cli
Vendor: Cylon Chau
Source1: cli
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package server
Summary: The binary file of kubernetes control plane.
Group: Kubernetes/Server
Vendor:  Cylon Chau
Source2: server
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package admincfg
Summary: The administration configration file of kubernetes cluster.
Group: Kubernetes/Admin
Vendor: Cylon Chau
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client
Summary: The binary file of kubernetes client.
Group: Kubernetes/Client
Vendor: Cylon Chau
Source3: client
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package client-certificates
Summary: The certificates of kubernetes client.
Group: Kubernetes/Certificates
Vendor: Cylon Chau
URL: https://github.com/cylonChau/kubernetes-generator
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot

%package etcd-certificates
Summary: The certificates of etcd cluster.
Group:Applications/Certificates
Vendor: Cylon Chau
Source4: etcd
URL: https://github.com/cylonChau/kubernetes-generator
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
%{__install} -d %{buildroot}${CLIENT_BIN_DIR}
%{__install} -d %{buildroot}${SERVER_BIN_DIR}
%{__install} -d %{buildroot}/usr/lib/systemd/system/
%{__install} -d  %{buildroot}/etc/kubernetes/

%{__install} -d  %{buildroot}/etc/etcd/

%{__cp} -a %{SOURCE2}/bin/* %{buildroot}${SERVER_BIN_DIR}
%{__cp} -a %{SOURCE2}/etc/* %{buildroot}/etc/kubernetes/
%{__cp} -a %{SOURCE2}/systemd/* %{buildroot}/usr/lib/systemd/system/

%{__cp} -a %{SOURCE3}/bin/* %{buildroot}${CLIENT_BIN_DIR}
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
%attr(0755,root,root) ${CLIENT_BIN_DIR}/kubelet
%attr(0755,root,root) ${CLIENT_BIN_DIR}/kube-proxy
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
[ -d /var/lib/kubelet ] || mkdir -pv /var/lib/kubelet
echo -e "\033[32m Don't forget to modify the kubelet and kube-proxy configuration file. \033[0m"

%postun server
id kube && userdel -r kube

%postun client
echo -e "\033[32m Automatically clean up working directory [/var/lib/kubelet]. \033[0m"
[ -d /var/lib/kubelet ] || rm -fr /var/lib/kubelet

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
URL: https://github.com/cylonChau/kubernetes-generator
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

function CLEAN_WORK_DIR(){
    if [ ${ISRPM} == "Y" ];then
        rm -fr ${WORK_DIR}/{kubernetes,rsyslog,system,bin,cert}
        echo -n -e "\n\033[31mPlease install the files under the [${WORK_DIR}/rpms] path directly. \033[0m\n"
    else
        END
    fi
}

function MAIN(){
    set_cert_evn kubernetes
    echo -n -e "generated content\n    1.only certificates for etcd and kubernetes.\n    2.only donwload kubernetes\n    3.certificates and config files.\n"
    read -p "Please enter the which to generate [3]: " INSTALL_OPS
    INSTALL_OPS=${INSTALL_OPS:-3}

    case ${INSTALL_OPS} in
    1)
        set_env
        DownloadKube
        ExtractKube
        Generate_Certificates
        CleanBin
        ;;
    2)  
        set_env
        DownloadKube
        ExtractKube
        ;;
    3)
        set_env
        DownloadKube
        ExtractKube
        Generate_Certificates
        ActionInitail
        RPM
        CLEAN_WORK_DIR
        ;;
    *)  
        echo -e "\033[41;37millegal option\033[0m" 
        ;;
    esac 
}
MAIN
