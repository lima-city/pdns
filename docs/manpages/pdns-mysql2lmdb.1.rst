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
instead of applying a partial update.  In all incremental cases each affected
zone is fetched from MySQL and atomically rewritten in LMDB.  This intentionally
avoids maintaining a second record-level replication implementation for the LMDB
backend.

If the saved binary log position is no longer available, the tool performs
another full resync and resumes incremental replication from the new snapshot
position.  Transient ``mysqlbinlog`` disconnects reconnect from the last fully
applied and flushed position instead of forcing a full resync.

Operational progress is logged to standard error.  The log includes startup
configuration, whether a saved state file was found, full-resync reasons and
snapshot positions, incremental binlog positions, binlog rotations, changed and
deleted zone counts, TSIG refreshes, and state-file updates.

REQUIREMENTS
------------

The MySQL primary must have binary logging enabled.  ``binlog_format=ROW`` is
the most efficient mode because it identifies changed rows precisely.
``MIXED`` and ``STATEMENT`` are supported, but complex statements can cause a
full resync when the changed zone cannot be inferred safely.
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

--lmdb-filename=PATH     Target LMDB backend file. Defaults to ``./pdns.lmdb``.

--lmdb-sync-mode=MODE    LMDB synchronization mode. Defaults to ``nosync`` for
                        this importer; the tool explicitly syncs LMDB before
                        saving each applied binlog position.

--state-file=PATH        File storing the last applied binlog position. Relative
                        paths are resolved below the directory containing
                        ``--lmdb-filename``. Absolute paths are used unchanged.

--full                  Force a full resync before following the binlog.

--once                  Exit after the initial full resync or after one binlog
                        stream attempt.

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

OPERATIONAL NOTES
-----------------

Empty non-terminals stored by the Generic MySQL backend as records with
``type=NULL`` are imported as LMDB ENT entries.  For NSEC3 zones, order names are
interpreted based on the zone's ``NSEC3PARAM`` and ``NSEC3NARROW`` metadata.

Externally created or deleted zones are noticed by a running ``pdns_server``
after its regular zone-cache refresh interval unless the cache is flushed by
other means.  The default refresh interval is 300 seconds.
