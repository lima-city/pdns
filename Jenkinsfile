pipeline {
    agent { label "apt-repo" }

    options {
        timestamps()
    }

    stages {
        stage('Build Debian packages') {
            steps {
                sh '''
set -eux

. deb-package/package.env

: "${PACKAGE_VERSION:?}"
: "${PACKAGE_ITERATION:?}"
: "${UBUNTU_RELEASES:?}"

for release in ${UBUNTU_RELEASES}; do
    out_dir="deb-package/out/${release}"
    publish_dir="/tmp/deb-publish-${release}"

    rm -rf "${out_dir}" "${publish_dir}"

    docker build \
        -f deb-package/Dockerfile \
        --target export-stage \
        --build-arg UBUNTU_RELEASE="${release}" \
        --build-arg PACKAGE_VERSION="${PACKAGE_VERSION}" \
        --build-arg PACKAGE_ITERATION="${PACKAGE_ITERATION}~${release}" \
        --output "type=local,dest=${out_dir}" \
        .

    install -d -m 0755 "${publish_dir}"
    install -m 0644 "${out_dir}"/*.deb "${publish_dir}/"
done
'''
            }
        }

        stage('Publish Debian packages') {
            steps {
                sh '''
set -eux

. deb-package/package.env

: "${PUBLISH_RELEASES:?}"

echo "************ RELEASING pdns-mysql2lmdb ************"

for release in ${PUBLISH_RELEASES}; do
    sudo -n -H -u apt-repo /usr/local/bin/publish-deb "${release}" "/tmp/deb-publish-${release}"/*.deb
done
'''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'deb-package/out/*/*.deb', allowEmptyArchive: true, fingerprint: true
        }
    }
}
