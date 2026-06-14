# pdns-mysql2lmdb Debian Package

Build the package from the repository root:

```sh
docker build \
  -f deb-package/Dockerfile \
  --target export-stage \
  --build-arg UBUNTU_RELEASE=noble \
  --build-arg PACKAGE_VERSION=0.1.0 \
  --build-arg PACKAGE_ITERATION=1noble \
  --output type=local,dest=deb-package/out/noble \
  .
```

For a CI matrix build, pass the Ubuntu release as a build argument and write each
release into a separate output directory:

```sh
for release in jammy noble; do
  docker build \
    -f deb-package/Dockerfile \
    --target export-stage \
    --build-arg UBUNTU_RELEASE="${release}" \
    --build-arg PACKAGE_VERSION=0.1.0 \
    --build-arg PACKAGE_ITERATION="1${release}" \
    --output "type=local,dest=deb-package/out/${release}" \
    .
done
```

Runtime library dependencies are generated inside the selected Ubuntu release
with `dpkg-shlibdeps`, so package names such as OpenSSL, Boost, glibc and
libstdc++ match the target release.

The Dockerfile pins Meson inside the build container, because older Ubuntu
releases can ship a Meson version that is too old for the current PowerDNS
build files.
