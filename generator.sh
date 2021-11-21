#!/bin/bash -e

function usage() {
    >&2 cat << EOF
Set the following environment variables to run this script:

Usage: ${0} etcd|k8s
    k8s      generate certificates of kubernetes.
    etcd     generate certificates of etcd.
EOF
    exit 1
}

function set_evn(){
    DIR=${DIR:-generate}
    if [ ${#} -eq 1 ]; then
        DIR="$1"
    fi
    echo $DIR
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
    case "$1" in
	"k8s"|"kubernetes")

        read -p "Pls Enter Kubernetes Cluster Name [kubernetes]: " CLUSTER_NAME
        echo -n -e "Enter the IP Address in default namespace \n of the Kubernetes API Server[10.96.0.1]: "
        read  APISERVER_CLUSTER_IP
        read -p "Pls Enter Master servers name[master01 master02 master03]: " MASTERS

        CLUSTER_NAME=${CLUSTER_NAME:-kubernetes}
        APISERVER_CLUSTER_IP=${APISERVER_CLUSTER_IP:-10.96.0.1}
        MASTERS=${MASTERS:-"master01 master02 master03"}

        read -p "Pls Enter CA Common Name [k8s-ca]: " CERT_CN
        CERT_CN=${CERT_CN:-k8s-ca}

        read -p "Pls Enter Certificate validity period [3650]: " EXPIRED_DAYS
        EXPIRED_DAYS=${EXPIRED_DAYS:-3650}

        export CLUSTER_NAME APISERVER_CLUSTER_IP MASTERS CERT_CN EXPIRED_DAYS

        export CA_CERT="$CERT_DIR/ca.crt"
        export CA_KEY="$CERT_DIR/ca.key"
        if [ -f "$CA_CERT" -a -f "$CA_KEY" ]; then
            echo "Using the CA: $CA_CERT and $CA_KEY"
            read -p "pause" A
        else
            echo "Generating CA key and self signed cert." 
            openssl genrsa -out $CERT_DIR/ca.key 4096
            openssl req -config openssl.conf \
                -new -x509 -days 3650 -sha256 \
                -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt \
            -subj "/CN=${CERT_CN}"
        fi

		;;
    "etcd"|"ETCD")
        read -p "Pls Enter Domain Name [my-k8s.example.com|example_name]: " BASE_DOMAIN
        BASE_DOMAIN=${BASE_DOMAIN:-k8s.io}

        read -p "Pls Enter Organization Name [chinamobile]: " CERT_O
        CERT_O=${CERT_O:-chinamobile}

        read -p "Pls Enter CA Common Name [ectd-ca]: " CERT_CN
        CERT_CN=${CERT_CN:-etcd-ca}

        read -p "Pls Enter Certificate validity period [3650]: " EXPIRED_DAYS
        EXPIRED_DAYS=${EXPIRED_DAYS:-3650}
        
        export BASE_DOMAIN CERT_O CERT_CN EXPIRED_DAYS
        ;;
    esac
}


function openssl_req() {
    openssl genrsa -out ${1}/${2}.key 2048
    echo "Generating ${1}/${2}.csr"
    echo $BASE_DOMAIN
    openssl req -config openssl.conf -new -sha256 \
        -key ${1}/${2}.key -out ${1}/${2}.csr -subj "$3"
}

function openssl_sign() {
    echo "Generating ${3}/${4}.crt"
    openssl ca -batch -config openssl.conf -extensions $5 -days ${EXPIRED_DAYS} -notext \
        -md sha256 -in ${3}/${4}.csr -out ${3}/${4}.crt \
        -cert ${1} -keyfile ${2}
}


function generate_kubernetes_certificates() {
    # If supplied, generate a new etcd CA and associated certs.
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
        cp $ETCD_CERTS_DIR/pki/apiserver-etcd-client.{key,crt} ${master_dir}/pki/
        fi

        # echo "Generating kubeconfig for kube-controller-manager"
        cat > ${master_dir}/auth/controller-manager.conf << EOF
    apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
cluster:
    server: https://${master}.${BASE_DOMAIN}:6443
    certificate-authority-data: $( openssl base64 -A -in $CA_CERT ) 
users:
- name: system:kube-controller-manager
user:
    client-certificate-data: $( openssl base64 -A -in ${master_dir}/pki/kube-controller-manager.crt ) 
    client-key-data: $( openssl base64 -A -in ${master_dir}/pki/kube-controller-manager.key ) 
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: system:kube-controller-manager
name: system:kube-controller-manager@${CLUSTER_NAME}
current-context: system:kube-controller-manager@${CLUSTER_NAME}
EOF

        # echo "Generating kubeconfig for kube-scheduler"
        cat > ${master_dir}/auth/scheduler.conf << EOF
apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
cluster:
    server: https://${master}.${BASE_DOMAIN}:6443
    certificate-authority-data: $( openssl base64 -A -in $CA_CERT ) 
users:
- name: system:kube-scheduler
user:
    client-certificate-data: $( openssl base64 -A -in ${master_dir}/pki/kube-scheduler.crt ) 
    client-key-data: $( openssl base64 -A -in ${master_dir}/pki/kube-scheduler.key ) 
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: system:kube-scheduler
name: system:kube-scheduler@${CLUSTER_NAME}
current-context: system:kube-scheduler@${CLUSTER_NAME}
EOF

        # echo "Generating kubeconfig for Cluster Admin"
        cat > ${master_dir}/auth/admin.conf << EOF
apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
cluster:
    server: https://${master}.${BASE_DOMAIN}:6443
    certificate-authority-data: $( openssl base64 -A -in $CA_CERT ) 
users:
- name: k8s-admin
user:
    client-certificate-data: $( openssl base64 -A -in ${master_dir}/pki/apiserver-kubelet-client.crt ) 
    client-key-data: $( openssl base64 -A -in ${master_dir}/pki/apiserver-kubelet-client.key ) 
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: k8s-admin
name: k8s-admin@${CLUSTER_NAME}
current-context: k8s-admin@${CLUSTER_NAME}
EOF
    done


    # Generate key and cert for kubelet
    kubelet_dir=${DIR}/kubelet
    mkdir -p ${kubelet_dir}/{pki,auth}

    openssl_req ${kubelet_dir}/pki kube-proxy "/CN=system:kube-proxy"
    openssl_sign $CA_CERT $CA_KEY ${kubelet_dir}/pki kube-proxy client_cert
    rm -f ${kubelet_dir}/pki/kube-proxy.csr

    # Copy CA Cert to Node
    cp $CA_CERT ${kubelet_dir}/pki/

    cat > ${kubelet_dir}/auth/kube-proxy.conf << EOF
apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
cluster:
    server: https://${CLUSTER_NAME}-api.${BASE_DOMAIN}:6443
    certificate-authority-data: $( openssl base64 -A -in $CA_CERT ) 
users:
- name: system:kube-proxy
user:
    client-certificate-data: $( openssl base64 -A -in ${kubelet_dir}/pki/kube-proxy.crt ) 
    client-key-data: $( openssl base64 -A -in ${kubelet_dir}/pki/kube-proxy.key ) 
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: system:kube-proxy
name: system:kube-proxy@${CLUSTER_NAME}
current-context: system:kube-proxy@${CLUSTER_NAME}
EOF

    cat > ${kubelet_dir}/auth/bootstrap.conf << EOF
apiVersion: v1
kind: Config
clusters:
- name: ${CLUSTER_NAME}
cluster:
    server: https://${CLUSTER_NAME}-api.${BASE_DOMAIN}:6443
    certificate-authority-data: $( openssl base64 -A -in $CA_CERT ) 
users:
- name: system:bootstrapper
user:
    token: ${BOOTSTRAP_TOKEN}
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: system:bootstrapper
name: system:bootstrapper@${CLUSTER_NAME}
current-context: system:bootstrapper@${CLUSTER_NAME}
EOF

    # Generate key and cert for ingress
    ingress_dir=${DIR}/ingress
    mkdir -p ${DIR}/ingress/patches

    openssl_req ${ingress_dir} ingress-server "/CN=${CLUSTER_NAME}.${BASE_DOMAIN}"
    openssl_sign $CA_CERT $CA_KEY ${ingress_dir} ingress-server server_cert
    rm -f ${ingress_dir}/*.csr

    # Generate secret patches. We include the metadata here so
    # `kubectl patch -f ( file ) -p $( cat ( file ) )` works.
    cat > ${ingress_dir}/patches/ingress-tls.patch << EOF
apiVersion: v1
kind: Secret
metadata:
name: ingress-tls-secret
namespace: kube-system
data:
tls.crt: $( openssl base64 -A -in ${ingress_dir}/ingress-server.crt )
tls.key: $( openssl base64 -A -in ${ingress_dir}/ingress-server.key )
EOF

    # Clean up openssl config
    rm -f $CERT_DIR/index*
    rm -f $CERT_DIR/100*
    rm -f $CERT_DIR/serial*
    rm -f /tmp/token.csv
}


function generate_etcd_certificates() {
        if [ -z "$CA_KEY" -o -z "$CA_CERT" ]; then
        openssl genrsa -out $CERT_DIR/ca.key 4096
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

    ETCD_PATCHES=$DIR/patches
    mkdir -p $ETCD_PATCHES

    # kubectl apply 
    cat > $ETCD_PATCHES/etcd-client-cert.patch << EOF
apiVersion: v1
kind: Secret
metadata:
name: kube-apiserver
namespace: kube-system
data:
etcd-client.crt: $( openssl base64 -A -in ${CERT_DIR}/client.crt )
etcd-client.key: $( openssl base64 -A -in ${CERT_DIR}/client.key )
EOF

    # Clean up openssl config
    rm $CERT_DIR/index*
    rm $CERT_DIR/100*
    rm $CERT_DIR/serial*
    rm $CERT_DIR/*.csr
}

case "$1" in
	"k8s"|"K8S"|"kubernetes"|"KUBERNETES")
        set_evn kubernetes
        generate_kubernetes_certificates
		;;
    "etcd"|"ETCD")
        set_evn etcd
        generate_etcd_certificates
        ;; 
	*)
		usage
	    ;;
esac