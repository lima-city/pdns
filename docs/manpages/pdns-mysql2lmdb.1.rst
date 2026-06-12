pdns-mysql2lmdb(1)
==================

SYNOPSIS
--------

pdns-mysql2lmdb [OPTION]...

DESCRIPTION
-----------

``pdns-mysql2lmdb`` replicates an authoritative PowerDNS Generic MySQL
database into a local LMDB backend database.

The tool performs an initial full resync when no saved replication state is
available, or when ``--full`` is specified.  The full resync is taken from a
consistent InnoDB snapshot and records the MySQL primary binary log position
that belongs to that snapshot.  Local LMDB zones are replaced zone by zone.
Zones that no longer exist on the MySQL primary are removed locally.

After the full resync, the tool follows the primary's binary log via
``mysqlbinlog``.  ROW, MIXED and STATEMENT binary logs are supported.  Row
events are used to identify affected PowerDNS zones directly and require
``binlog_row_image=FULL``.  Statement events are inspected for affected PowerDNS
tables and zone identifiers.  If a binlog event touches PowerDNS data but the
affected zone cannot be identified safely, the tool performs a full resync
instead of applying a partial update.  Record, comment, metadata and key changes
fetch each affected zone from MySQL and atomically rewrite it in LMDB.  Domain
row updates that do not rename the zone update LMDB DomainInfo only, avoiding a
full record rewrite for notification and health-check fields.

If the saved binary log position is no longer available, the tool performs
another full resync and resumes incremental replication from the new snapshot
position.  Transient ``mysqlbinlog`` disconnects reconnect from the last fully
applied and flushed position instead of forcing a full resync.

Operational progress is logged to standard error.  The log includes startup
configuration, whether a saved state file was found, full-resync reasons and
snapshot positions, incremental binlog positions, binlog rotations, changed and
deleted zone counts, TSIG refreshes, and state-file updates.

For benchmarking and operational checks, the tool also has two one-shot modes
that do not use ``mysqlbinlog`` and do not read or write the replication state
file.  ``--sync-zone=ZONE`` synchronizes exactly one zone and exits.
``--serial-scan`` reads all MySQL apex SOA serials, compares them with local
LMDB SOA serials, synchronizes missing or changed zones, removes local zones
that no longer exist in MySQL, refreshes TSIG keys, and exits.  These modes are
intended to measure whether periodic SOA-serial polling is viable without
changing the default binlog-following daemon.

REQUIREMENTS
------------

The MySQL primary must have binary logging enabled.  ``binlog_format=ROW`` is
strongly recommended for production because it identifies changed rows
precisely and avoids statement-text parsing edge cases.  ``MIXED`` and
``STATEMENT`` are supported, but complex statements can cause a full resync when
the changed zone cannot be inferred safely.
``binlog_row_image`` must be ``FULL`` so row events include enough data to map
changes back to zones.  The MySQL user needs privileges to read the PowerDNS
tables, execute ``SHOW MASTER STATUS`` or ``SHOW BINARY LOG STATUS`` and
``FLUSH TABLES WITH READ LOCK``, and stream binary logs.

The ``mysqlbinlog`` client must be installed on the host running the tool.

OPTIONS
-------

--mysql-host=HOST        MySQL primary host. Defaults to ``127.0.0.1``.

--mysql-port=PORT        MySQL primary port. Defaults to ``3306``.

--mysql-socket=PATH      MySQL Unix socket.

--mysql-user=USER        MySQL replication user. Defaults to ``powerdns``.

--mysql-password=PASS    MySQL replication user password.

--mysql-defaults-file=PATH
                        MySQL defaults file containing client credentials.
                        Prefer this over ``--mysql-password`` for production
                        deployments.  When set, host, port, user, password and
                        socket are read from the file's ``[client]`` section
                        unless the corresponding command-line option is set to
                        a non-default value.  The same file is passed to
                        ``mysqlbinlog`` as its first option.

                        Incremental replication does not pass
                        ``--mysql-password`` to ``mysqlbinlog`` because command
                        line passwords are visible in process listings.  Use a
                        defaults file whenever ``mysqlbinlog`` needs a password.

--mysql-dbname=NAME      MySQL PowerDNS database name. Defaults to ``powerdns``.

--mysqlbinlog=PATH       Path to the ``mysqlbinlog`` client.

--sync-zone=ZONE         Synchronize one zone from MySQL to LMDB and exit.  The
                        zone is read from a consistent MySQL snapshot and then
                        atomically rewritten in LMDB.  The completion log
                        includes imported record, empty-non-terminal, comment,
                        metadata and key counts, elapsed seconds, and
                        records per second.  This mode does not require
                        ``mysqlbinlog`` and does not use ``--state-file``.

--lmdb-filename=PATH     Target LMDB backend file. Defaults to ``./pdns.lmdb``.

--lmdb-sync-mode=MODE    LMDB synchronization mode. Defaults to ``nosync`` for
                        this importer; the tool explicitly syncs changed LMDB
                        environments before saving applied binlog positions.

--state-file=PATH        File storing the last applied binlog position. Relative
                        paths are resolved below the directory containing
                        ``--lmdb-filename``. Absolute paths are used unchanged.

--state-save-transactions=NUM
                        Number of applied binlog transactions to coalesce before
                        syncing LMDB and saving the replication state. Defaults
                        to ``100``.

--state-save-interval=MSEC
                        Maximum milliseconds to coalesce before syncing LMDB and
                        saving a pending applied replication state, evaluated
                        when another binlog transaction is applied.  An idle
                        binlog stream may keep the pending state in memory until
                        the next event, clean shutdown, reconnect or
                        ``--once`` exit. Defaults to ``1000``.

--full                  Force a full resync before following the binlog.

--once                  Exit after the initial full resync or after one binlog
                        stream attempt.

--serial-scan           Compare MySQL apex SOA serials with local LMDB SOA
                        serials, synchronize missing or changed zones, delete
                        stale local zones, refresh TSIG keys, and exit.  The
                        MySQL serials are read directly from ``domains`` joined
                        to enabled apex ``SOA`` rows in ``records``.  Domains
                        without a readable enabled apex SOA follow the
                        ``--invalid-records`` policy.  This mode does not
                        require ``mysqlbinlog`` and does not use
                        ``--state-file``.

--retry-interval=SEC     Seconds to wait before reconnecting a stopped binlog
                        stream.

--soa-serial-overflow=MODE
                        How to handle SOA serials larger than the DNS 32-bit
                        maximum. ``reject`` fails with the affected zone and
                        record name, ``modulo`` stores the low 32 bits, and
                        ``clamp`` stores ``4294967295``. Defaults to
                        ``reject``.

--invalid-records=MODE
                        How to handle MySQL records that cannot be parsed or
                        serialized as DNS data. ``reject`` fails with the
                        affected MySQL record id, zone, name and type.
                        ``skip`` logs a warning and omits the invalid record.
                        For DNSSEC keys, ``skip`` omits unparsable key rows
                        instead of stopping replication. Defaults to ``reject``.

--allow-missing-mysqlbinlog
                        Allow startup when the configured ``mysqlbinlog``
                        executable is missing.  This is only useful for
                        one-shot full-resync testing because incremental
                        replication requires ``mysqlbinlog``.

--help                  Show available options.

EXAMPLES
--------

Synchronize one large zone into a scratch LMDB database and log throughput::

  pdns-mysql2lmdb --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/tmp/pdns-bench.lmdb --sync-zone=example.org

Run a one-shot SOA-serial scan against an existing benchmark LMDB database::

  pdns-mysql2lmdb --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/tmp/pdns-bench.lmdb --serial-scan

OPERATIONAL NOTES
-----------------

Empty non-terminals stored by the Generic MySQL backend as records with
``type=NULL`` are imported as LMDB ENT entries.  For NSEC3 zones, order names are
interpreted based on the zone's ``NSEC3PARAM`` and ``NSEC3NARROW`` metadata.

When ``--invalid-records=skip`` skips all DNSSEC keys for a signed zone, the
zone is left unchanged in LMDB and is retried only when a later event touches the
zone again or a full resync is forced.  Operators should monitor skip warnings
and trigger a resync after repairing source data if immediate convergence is
required.

If the tool restarts after a MySQL ``ALTER TABLE`` but before the corresponding
binlog event is replayed, row events generated before the DDL can be decoded
with the newer column map.  The importer falls back to a full resync when it
reaches the unsafe event, but a short transient window can remain.  Avoid schema
changes while the importer is stopped.

In ``STATEMENT`` or ``MIXED`` mode, statement values containing literal newline
characters are rendered by ``mysqlbinlog`` as physical output lines.  Such lines
can resemble mysqlbinlog headers or diagnostics.  Use ``binlog_format=ROW`` for
production deployments to avoid this class of ambiguity.

Externally created or deleted zones are noticed by a running ``pdns_server``
after its regular zone-cache refresh interval unless the cache is flushed by
other means.  The default refresh interval is 300 seconds.
