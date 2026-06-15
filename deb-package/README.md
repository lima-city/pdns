# pdns-mysql2lmdb Debian Package

Build the package from the repository root:

```sh
. deb-package/package.env

docker build \
  -f deb-package/Dockerfile \
  --target export-stage \
  --build-arg UBUNTU_RELEASE=noble \
  --build-arg PACKAGE_VERSION="${PACKAGE_VERSION}" \
  --build-arg PACKAGE_ITERATION="${PACKAGE_ITERATION}~noble" \
  --output type=local,dest=deb-package/out/noble \
  .
```

The package version is controlled in `deb-package/package.env`. Bump
`PACKAGE_VERSION` for upstream releases and `PACKAGE_ITERATION` for packaging
revisions of the same upstream version. The Ubuntu release suffix is appended by
the build command as `~jammy` or `~noble`.

Jenkins should use the repository `Jenkinsfile` as a Pipeline from SCM. The
Jenkins job then no longer contains release versions; it checks out this
repository, sources `deb-package/package.env`, builds all configured Ubuntu
releases, and publishes the resulting packages.

For a CI matrix build, pass the Ubuntu release as a build argument and write each
release into a separate output directory:

```sh
. deb-package/package.env

for release in ${UBUNTU_RELEASES}; do
  docker build \
    -f deb-package/Dockerfile \
    --target export-stage \
    --build-arg UBUNTU_RELEASE="${release}" \
    --build-arg PACKAGE_VERSION="${PACKAGE_VERSION}" \
    --build-arg PACKAGE_ITERATION="${PACKAGE_ITERATION}~${release}" \
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

## Runtime schema contract

The default polling mode uses an extended PowerDNS MySQL schema. The `domains`
table must contain the zone-wide replication cursor:

```sql
ALTER TABLE domains
  ADD COLUMN last_replicated_change_at INT UNSIGNED NOT NULL DEFAULT 0,
  ADD INDEX domains_last_replicated_change_at_idx (last_replicated_change_at, id);
```

Every zone-relevant application change must update the apex SOA serial and set
`domains.last_replicated_change_at = UNIX_TIMESTAMP()` in the same MySQL
transaction.
