pdns-mysql2lmdb(1)
==================

SYNOPSIS
--------

pdns-mysql2lmdb [OPTION]...

DESCRIPTION
-----------

``pdns-mysql2lmdb`` replicates an authoritative PowerDNS Generic MySQL
database into a local LMDB backend database.

By default the tool runs as a SOA-serial polling daemon.  It first performs a
complete SOA serial scan, then every ``--poll-interval`` seconds it reads zones
whose ``domains.last_replicated_change_at`` value is newer than or equal to the
last polling cursor.  The cursor is the highest
``domains.last_replicated_change_at`` value read from the source, and it
intentionally overlaps that value so updates with the same timestamp are read
again.
Every ``--full-sweep-interval`` seconds it runs another complete SOA serial scan
to catch deleted zones, missing zones and out-of-band source changes.  Missing
or changed zones are synchronized by rewriting the complete zone in LMDB.  Zone
metadata and DNSSEC keys are committed before the records, so the local SOA
serial only advances after the side data has already converged.  TSIG keys are
refreshed and dirty LMDB environments are synced after each round.  The default
mode does not use ``mysqlbinlog`` and does not read or write the replication
state file.

For benchmarking and operational checks, ``--sync-zone=ZONE`` synchronizes
exactly one zone and exits.  ``--serial-scan`` runs one SOA-serial polling
round and exits.

The previous binlog-following replication mode is still available with
``--binlog-follow``.  In that mode the tool performs an initial full resync
when no saved replication state is available, or when ``--full`` is specified.
The full resync is taken from a consistent InnoDB snapshot and records the MySQL
primary binary log position that belongs to that snapshot.  After the full
resync, the tool follows the primary's binary log via ``mysqlbinlog``.  ROW,
MIXED and STATEMENT binary logs are supported.  Row events are used to identify
affected PowerDNS zones directly and require ``binlog_row_image=FULL``.
Statement events are inspected for affected PowerDNS tables and zone
identifiers.  If a binlog event touches PowerDNS data but the affected zone
cannot be identified safely, the tool performs a full resync instead of
applying a partial update.

Operational progress is logged to standard error.  The log includes startup
configuration, polling-round summaries, changed and deleted zone counts, TSIG
refreshes, and, in legacy binlog-following mode, binlog positions and
state-file updates.

REQUIREMENTS
------------

The default SOA-serial polling mode requires an extended PowerDNS MySQL schema
with a ``domains.last_replicated_change_at`` column.  Every relevant zone change
must update that zone's apex SOA serial and set
``domains.last_replicated_change_at`` to the MySQL server's current
``UNIX_TIMESTAMP()`` value in the same transaction.  The column should be
indexed, preferably with ``last_replicated_change_at`` as the first indexed
column.  The MySQL user needs privileges to read the PowerDNS ``domains``,
``records``, ``comments``, ``domainmetadata``, ``cryptokeys`` and ``tsigkeys``
tables.

Legacy ``--binlog-follow`` mode additionally requires binary logging on the
MySQL primary.  ``binlog_format=ROW`` is strongly recommended for production
because it identifies changed rows precisely and avoids statement-text parsing
edge cases.  ``MIXED`` and ``STATEMENT`` are supported, but complex statements
can cause a full resync when the changed zone cannot be inferred safely.
``binlog_row_image`` must be ``FULL`` so row events include enough data to map
changes back to zones.  The MySQL user also needs privileges to execute
``SHOW MASTER STATUS`` or ``SHOW BINARY LOG STATUS``, execute a global read
lock, and stream binary logs.  The ``mysqlbinlog`` client must be installed on
the host running the tool only when ``--binlog-follow`` is used.

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
                        a non-default value.  In ``--binlog-follow`` mode, the
                        same file is passed to ``mysqlbinlog`` as its first
                        option.

                        ``--binlog-follow`` mode does not pass
                        ``--mysql-password`` to ``mysqlbinlog`` because command
                        line passwords are visible in process listings.  Use a
                        defaults file whenever ``mysqlbinlog`` needs a password.

--mysql-dbname=NAME      MySQL PowerDNS database name. Defaults to ``powerdns``.

--mysqlbinlog=PATH       Path to the ``mysqlbinlog`` client for
                        ``--binlog-follow`` mode.

--sync-zone=ZONE         Synchronize one zone from MySQL to LMDB and exit.  The
                        zone is read from a consistent MySQL snapshot and then
                        rewritten in LMDB with records and the local SOA serial
                        committed last.  The completion log includes imported
                        record, empty-non-terminal, comment, metadata and key
                        counts, elapsed seconds, and records per second.  This
                        mode does not require ``mysqlbinlog`` and does not use
                        ``--state-file``.

--lmdb-filename=PATH     Target LMDB backend file. Defaults to ``./pdns.lmdb``.

--lmdb-sync-mode=MODE    LMDB synchronization mode. Defaults to ``nosync`` for
                        this importer; the tool explicitly syncs changed LMDB
                        environments after polling rounds and before saving
                        applied binlog positions in ``--binlog-follow`` mode.

--poll-interval=SEC      Seconds to wait between SOA-serial polling rounds in
                        the default daemon mode. After the initial complete
                        scan, regular rounds use the
                        ``domains.last_replicated_change_at`` cursor. Defaults
                        to ``5``.

--full-sweep-interval=SEC
                        Seconds between complete SOA serial sweeps in the
                        default daemon mode. A full sweep catches stale local
                        zones, missing zones and source changes not visible via
                        the ``domains.last_replicated_change_at`` diff query.
                        ``0`` disables periodic full sweeps after the initial
                        complete scan. Defaults to ``300``.

--binlog-follow          Use the legacy ``mysqlbinlog``-following replication
                        mode instead of the default SOA-serial polling daemon.

--state-file=PATH        File storing the last applied binlog position in
                        ``--binlog-follow`` mode. Relative paths are resolved
                        below the directory containing ``--lmdb-filename``.
                        Absolute paths are used unchanged.

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

--full                  In ``--binlog-follow`` mode, force a full resync before
                        following the binlog.

--once                  In the default daemon mode, exit after one SOA-serial
                        polling round.  In ``--binlog-follow`` mode, exit after
                        the initial full resync or after one binlog stream
                        attempt.

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
                        stream in ``--binlog-follow`` mode.

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
                        executable is missing in ``--binlog-follow`` mode.

--help                  Show available options.

EXAMPLES
--------

Run the default SOA-serial polling daemon::

  pdns-mysql2lmdb --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/var/lib/powerdns/pdns.lmdb --poll-interval=5

Synchronize one large zone into a scratch LMDB database and log throughput::

  pdns-mysql2lmdb --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/tmp/pdns-bench.lmdb --sync-zone=example.org

Run a one-shot SOA-serial scan against an existing benchmark LMDB database::

  pdns-mysql2lmdb --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/tmp/pdns-bench.lmdb --serial-scan

Run the legacy binlog-following daemon::

  pdns-mysql2lmdb --binlog-follow --mysql-defaults-file=/etc/pdns-mysql.cnf --mysql-dbname=powerdns --lmdb-filename=/var/lib/powerdns/pdns.lmdb

OPERATIONAL NOTES
-----------------

Empty non-terminals stored by the Generic MySQL backend as records with
``type=NULL`` are imported as LMDB ENT entries.  For NSEC3 zones, order names are
interpreted based on the zone's ``NSEC3PARAM`` and ``NSEC3NARROW`` metadata.

When ``--invalid-records=skip`` skips all DNSSEC keys for a signed zone, the
zone is left unchanged in LMDB and is retried during later polling rounds when
its MySQL SOA serial differs from the local LMDB serial.  Operators should
monitor skip warnings and repair source data if convergence is required.

In ``--binlog-follow`` mode, if the tool restarts after a MySQL ``ALTER TABLE``
but before the corresponding binlog event is replayed, row events generated
before the DDL can be decoded with the newer column map.  The importer falls
back to a full resync when it reaches the unsafe event, but a short transient
window can remain.  Avoid schema changes while the importer is stopped.

In ``--binlog-follow`` mode with ``STATEMENT`` or ``MIXED`` binlogs, statement
values containing literal newline characters are rendered by ``mysqlbinlog`` as
physical output lines.  Such lines can resemble mysqlbinlog headers or
diagnostics.  Use ``binlog_format=ROW`` for production deployments to avoid
this class of ambiguity.

Externally created or deleted zones are noticed by a running ``pdns_server``
after its regular zone-cache refresh interval unless the cache is flushed by
other means.  The default refresh interval is 300 seconds.
