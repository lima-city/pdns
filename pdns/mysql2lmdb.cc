/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "arguments.hh"
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "auth-zonecache.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "misc.hh"
#include "statbag.hh"
#include "utility.hh"
#include "logger.hh"
#include "modules/lmdbbackend/lmdbbackend.hh"

#include <mysql.h>
#include <errmsg.h>

#include <cerrno>
#include <csignal>
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <deque>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __GLIBC__
#include <malloc.h>
#endif

StatBag S;
AuthPacketCache PC;
AuthQueryCache QC;
AuthZoneCache g_zoneCache;
uint16_t g_maxNSEC3Iterations{0};
std::string g_memberCatalogGroup;
bool g_slogStructured{false};

ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

namespace
{

struct BinlogPosition
{
  std::string file;
  uint64_t pos{4};
};

struct MySQLDomain
{
  domainid_t id{UnknownDomainID};
  ZoneName name;
  std::string master;
  time_t lastCheck{0};
  DomainInfo::DomainKind kind{DomainInfo::Native};
  uint32_t notifiedSerial{0};
  std::string account;
  std::string options;
  ZoneName catalog;
};

struct MySQLRecord
{
  uint64_t id{0};
  std::string sourceName;
  std::string sourceType;
  std::string sourceContent;
  std::string sourceOrdername;
  DNSResourceRecord rr;
  bool hasOrdername{false};
  bool isENT{false};
};

struct MySQLComment
{
  Comment comment;
};

struct MySQLKey
{
  int id{0};
  unsigned int flags{0};
  bool active{false};
  bool published{true};
  std::string content;
};

struct NSEC3Settings
{
  bool present{false};
  NSEC3PARAMRecordContent param;
  bool narrow{false};
};

struct SnapshotRestartException : public std::runtime_error
{
  using std::runtime_error::runtime_error;
};

std::string getArg(const std::string& name)
{
  return ::arg()[name];
}

uint16_t getPort()
{
  return static_cast<uint16_t>(::arg().asNum("mysql-port"));
}

bool usingDefaultsFile()
{
  return !getArg("mysql-defaults-file").empty();
}

bool argDiffersFromDefault(const std::string& name)
{
  return getArg(name) != ::arg().getDefault(name);
}

uint16_t mysqlConnectPort()
{
  if (usingDefaultsFile() && !argDiffersFromDefault("mysql-port")) {
    return 0;
  }
  return getPort();
}

bool getBoolArg(const std::string& name)
{
  return ::arg().mustDo(name);
}

bool isAbsolutePath(const std::string& path)
{
  return !path.empty() && path.front() == '/';
}

std::string dirnameOf(const std::string& path)
{
  const auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return ".";
  }
  if (slash == 0) {
    return "/";
  }
  return path.substr(0, slash);
}

std::string basenameOf(const std::string& path)
{
  const auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return path;
  }
  return path.substr(slash + 1);
}

std::string joinPath(const std::string& directory, const std::string& filename)
{
  if (directory.empty() || directory == ".") {
    return filename;
  }
  if (directory == "/") {
    return "/" + filename;
  }
  return directory + "/" + filename;
}

std::string resolvedStateFile()
{
  const auto stateFile = getArg("state-file");
  if (isAbsolutePath(stateFile)) {
    return stateFile;
  }
  return joinPath(dirnameOf(getArg("lmdb-filename")), basenameOf(stateFile));
}

bool executableExists(const std::string& command)
{
  if (command.empty()) {
    return false;
  }
  if (command.find('/') != std::string::npos) {
    return access(command.c_str(), X_OK) == 0;
  }

  const char* pathEnv = std::getenv("PATH");
  if (pathEnv == nullptr) {
    return false;
  }

  std::vector<std::string> paths;
  stringtok(paths, pathEnv, ":");
  for (const auto& path : paths) {
    const auto candidate = (path.empty() ? std::string(".") : path) + "/" + command;
    if (access(candidate.c_str(), X_OK) == 0) {
      return true;
    }
  }
  return false;
}

std::string trim(const std::string& value)
{
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

void logInfo(const std::string& message)
{
  std::cerr << "Info: " << message << std::endl;
}

void logWarning(const std::string& message)
{
  std::cerr << "Warning: " << message << std::endl;
}

void trimAllocator(const std::string& context)
{
#ifdef __GLIBC__
  if (malloc_trim(0) != 0) {
    logInfo("released free heap to OS context='" + context + "'");
  }
#else
  (void)context;
#endif
}

std::string describePosition(const BinlogPosition& pos)
{
  return pos.file + ":" + std::to_string(pos.pos);
}

std::string summarizeZones(const std::set<ZoneName>& zones, size_t limit = 5)
{
  std::ostringstream out;
  out << zones.size();
  if (!zones.empty()) {
    out << " [";
    size_t count = 0;
    for (const auto& zone : zones) {
      if (count > 0) {
        out << ", ";
      }
      out << zone;
      ++count;
      if (count >= limit) {
        break;
      }
    }
    if (zones.size() > limit) {
      out << ", ...";
    }
    out << "]";
  }
  return out.str();
}

std::string oneLine(std::string value, size_t limit = 160)
{
  for (auto& chr : value) {
    if (chr == '\n' || chr == '\r' || chr == '\t') {
      chr = ' ';
    }
  }
  if (value.size() > limit) {
    value.resize(limit);
    value += "...";
  }
  return value;
}

std::string describeProcessStatus(int status)
{
  if (status == -1) {
    return "waitpid failed: " + stringerror();
  }
  if (WIFEXITED(status)) {
    return "exit_code=" + std::to_string(WEXITSTATUS(status)) + " raw_status=" + std::to_string(status);
  }
  if (WIFSIGNALED(status)) {
    return "signal=" + std::to_string(WTERMSIG(status)) + " raw_status=" + std::to_string(status);
  }
  return "raw_status=" + std::to_string(status);
}

void rememberOutputLine(std::deque<std::string>& lines, const std::string& line)
{
  lines.push_back(oneLine(line));
  while (lines.size() > 20) {
    lines.pop_front();
  }
}

void logRecentMysqlbinlogOutput(const std::deque<std::string>& lines)
{
  if (lines.empty()) {
    return;
  }
  logWarning("recent mysqlbinlog output before failure:");
  for (const auto& line : lines) {
    logWarning("  " + line);
  }
}

bool readPipeLine(FILE* stream, std::string& line)
{
  char* raw = nullptr;
  size_t size = 0;
  const auto length = ::getline(&raw, &size, stream);
  if (length < 0) {
    free(raw);
    return false;
  }
  line.assign(raw, static_cast<size_t>(length));
  free(raw);
  return true;
}

std::string toLowerASCII(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char chr) {
    return static_cast<char>(std::tolower(chr));
  });
  return value;
}

std::string toUpperASCII(std::string value)
{
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char chr) {
    return static_cast<char>(std::toupper(chr));
  });
  return value;
}

uint32_t handleUInt32Overflow(const std::string& field, uint64_t value, const std::string& context)
{
  if (value <= std::numeric_limits<uint32_t>::max()) {
    return static_cast<uint32_t>(value);
  }

  const auto mode = getArg("soa-serial-overflow");
  if (mode == "modulo") {
    const auto replacement = static_cast<uint32_t>(value);
    logWarning(field + " value " + std::to_string(value) + " " + context + " exceeds 32 bits; using modulo value " + std::to_string(replacement));
    return replacement;
  }
  if (mode == "clamp") {
    logWarning(field + " value " + std::to_string(value) + " " + context + " exceeds 32 bits; clamping to " + std::to_string(std::numeric_limits<uint32_t>::max()));
    return std::numeric_limits<uint32_t>::max();
  }

  throw std::runtime_error(field + " value " + std::to_string(value) + " " + context + " exceeds the DNS 32-bit maximum " + std::to_string(std::numeric_limits<uint32_t>::max()) + "; fix the source data or set --soa-serial-overflow=modulo/clamp");
}

uint32_t normalizeOptionalUInt32(const std::string& value, const std::string& field, const std::string& context)
{
  if (value.empty()) {
    return 0;
  }
  char* end = nullptr;
  errno = 0;
  const auto parsed = std::strtoull(value.c_str(), &end, 10);
  if (errno != 0 || end == value.c_str() || *end != '\0') {
    throw std::runtime_error("Unable to parse " + field + " value '" + value + "' " + context);
  }
  return handleUInt32Overflow(field, parsed, context);
}

std::string normalizeSOAContent(const ZoneName& zone, const DNSName& qname, const std::string& content)
{
  std::vector<std::string> parts;
  stringtok(parts, content, " \t");
  if (parts.size() < 7) {
    return content;
  }

  static const std::array<std::string, 5> fields{"SOA serial", "SOA refresh", "SOA retry", "SOA expire", "SOA minimum"};
  bool changed = false;
  const auto context = "for record '" + qname.toLogString() + "' in zone '" + zone.toLogString() + "'";
  for (size_t idx = 0; idx < fields.size(); ++idx) {
    const auto replacement = normalizeOptionalUInt32(parts.at(idx + 2), fields.at(idx), context);
    const auto replacementString = std::to_string(replacement);
    if (replacementString != parts.at(idx + 2)) {
      parts.at(idx + 2) = replacementString;
      changed = true;
    }
  }
  if (!changed) {
    return content;
  }

  std::ostringstream normalized;
  for (const auto& part : parts) {
    if (normalized.tellp() > 0) {
      normalized << ' ';
    }
    normalized << part;
  }
  return normalized.str();
}

class MySQL
{
public:
  MySQL()
  {
    connect();
  }

  ~MySQL()
  {
    close();
  }

  MySQL(const MySQL&) = delete;
  MySQL& operator=(const MySQL&) = delete;

  std::string escape(const std::string& input)
  {
    std::string output;
    output.resize((input.size() * 2) + 1);
    const auto length = mysql_real_escape_string(&d_mysql, output.data(), input.data(), input.size());
    output.resize(length);
    return output;
  }

  void execute(const std::string& query)
  {
    execute(query, true);
  }

  void executeTransactionQuery(const std::string& query)
  {
    execute(query, false);
  }

  void execute(const std::string& query, bool allowReconnect)
  {
    if (mysql_query(&d_mysql, query.c_str()) != 0) {
      if (allowReconnect && d_allowReconnect && isConnectionError()) {
        reconnect();
        if (mysql_query(&d_mysql, query.c_str()) == 0) {
          discardResults();
          return;
        }
      }
      throw error("Failed to execute query: " + query);
    }
    discardResults();
  }

  void discardResults()
  {
    while (auto* result = mysql_store_result(&d_mysql)) {
      mysql_free_result(result);
      if (mysql_next_result(&d_mysql) != 0) {
        return;
      }
    }
  }

  std::vector<std::vector<std::optional<std::string>>> query(const std::string& query)
  {
    if (mysql_query(&d_mysql, query.c_str()) != 0) {
      if (isConnectionError() && !d_allowReconnect) {
        throw SnapshotRestartException(error("MySQL connection lost while reading consistent snapshot: " + query).what());
      }
      if (isConnectionError()) {
        reconnect();
        if (mysql_query(&d_mysql, query.c_str()) == 0) {
          return storeQueryResult(query);
        }
      }
      throw error("Failed to execute query: " + query);
    }

    return storeQueryResult(query);
  }

  template <typename Callback>
  void forEachRow(const std::string& query, Callback callback)
  {
    if (mysql_query(&d_mysql, query.c_str()) != 0) {
      if (isConnectionError() && !d_allowReconnect) {
        throw SnapshotRestartException(error("MySQL connection lost while reading consistent snapshot: " + query).what());
      }
      if (isConnectionError()) {
        reconnect();
        if (mysql_query(&d_mysql, query.c_str()) != 0) {
          throw error("Failed to execute query: " + query);
        }
      }
      else {
        throw error("Failed to execute query: " + query);
      }
    }

    MYSQL_RES* result = mysql_use_result(&d_mysql);
    if (result == nullptr) {
      if (mysql_field_count(&d_mysql) == 0) {
        return;
      }
      throw error("Failed to stream query result: " + query);
    }

    const auto fields = mysql_num_fields(result);
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result)) != nullptr) {
      auto* lengths = mysql_fetch_lengths(result);
      std::vector<std::optional<std::string>> values;
      values.reserve(fields);
      for (unsigned int idx = 0; idx < fields; ++idx) {
        if (row[idx] == nullptr) {
          values.emplace_back(std::nullopt);
        }
        else {
          values.emplace_back(std::string(row[idx], lengths[idx]));
        }
      }
      callback(values);
    }
    mysql_free_result(result);
  }

  uint64_t connectionGeneration() const
  {
    return d_generation;
  }

  void setAllowReconnect(bool allow)
  {
    d_allowReconnect = allow;
  }

  bool allowReconnect() const
  {
    return d_allowReconnect;
  }

  void resetConnection()
  {
    reconnect();
  }

  std::vector<std::vector<std::optional<std::string>>> storeQueryResult(const std::string& query)
  {
    MYSQL_RES* result = mysql_store_result(&d_mysql);
    if (result == nullptr) {
      if (mysql_field_count(&d_mysql) == 0) {
        return {};
      }
      throw error("Failed to store query result: " + query);
    }

    const auto fields = mysql_num_fields(result);
    std::vector<std::vector<std::optional<std::string>>> rows;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(result)) != nullptr) {
      auto* lengths = mysql_fetch_lengths(result);
      std::vector<std::optional<std::string>> values;
      values.reserve(fields);
      for (unsigned int idx = 0; idx < fields; ++idx) {
        if (row[idx] == nullptr) {
          values.emplace_back(std::nullopt);
        }
        else {
          values.emplace_back(std::string(row[idx], lengths[idx]));
        }
      }
      rows.emplace_back(std::move(values));
    }
    mysql_free_result(result);
    return rows;
  }

  BinlogPosition masterStatus()
  {
    std::vector<std::vector<std::optional<std::string>>> rows;
    try {
      rows = query("SHOW MASTER STATUS");
    }
    catch (const std::runtime_error& e) {
      logWarning(std::string("SHOW MASTER STATUS failed, trying SHOW BINARY LOG STATUS: ") + e.what());
      rows = query("SHOW BINARY LOG STATUS");
    }
    if (rows.empty() || rows.at(0).size() < 2 || !rows.at(0).at(0) || !rows.at(0).at(1)) {
      throw std::runtime_error("MySQL did not return a binary log position");
    }
    return {*rows.at(0).at(0), static_cast<uint64_t>(std::stoull(*rows.at(0).at(1)))};
  }

  std::optional<std::string> nextBinaryLog(const std::string& current)
  {
    bool found = false;
    for (const auto& row : query("SHOW BINARY LOGS")) {
      if (row.empty() || !row.at(0)) {
        continue;
      }
      const auto file = *row.at(0);
      if (found) {
        return file;
      }
      found = file == current;
    }
    return std::nullopt;
  }

private:
  void connect()
  {
    d_host = getArg("mysql-host");
    d_user = getArg("mysql-user");
    d_password = getArg("mysql-password");
    d_dbname = getArg("mysql-dbname");
    d_socket = getArg("mysql-socket");
    d_defaultsFile = getArg("mysql-defaults-file");
    d_port = mysqlConnectPort();

    if (mysql_init(&d_mysql) == nullptr) {
      throw std::runtime_error("Unable to initialise MySQL client");
    }
    d_open = true;

    unsigned int timeout = static_cast<unsigned int>(::arg().asNum("mysql-timeout", 10));
    mysql_options(&d_mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(&d_mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
    mysql_options(&d_mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(&d_mysql, MYSQL_SET_CHARSET_NAME, "latin1");
    if (!d_defaultsFile.empty()) {
      mysql_options(&d_mysql, MYSQL_READ_DEFAULT_FILE, d_defaultsFile.c_str());
      mysql_options(&d_mysql, MYSQL_READ_DEFAULT_GROUP, "client");
    }

    const char* host = usingDefaultsFile() && !argDiffersFromDefault("mysql-host") ? nullptr : (d_host.empty() ? nullptr : d_host.c_str());
    const char* user = usingDefaultsFile() && !argDiffersFromDefault("mysql-user") ? nullptr : (d_user.empty() ? nullptr : d_user.c_str());
    const char* password = usingDefaultsFile() && !argDiffersFromDefault("mysql-password") ? nullptr : (d_password.empty() ? nullptr : d_password.c_str());
    const char* dbname = d_dbname.empty() ? nullptr : d_dbname.c_str();
    const char* socket = usingDefaultsFile() && !argDiffersFromDefault("mysql-socket") ? nullptr : (d_socket.empty() ? nullptr : d_socket.c_str());

    if (mysql_real_connect(&d_mysql, host, user, password, dbname, d_port, socket, CLIENT_MULTI_RESULTS) == nullptr) {
      throw error("Unable to connect to MySQL");
    }
    ++d_generation;
  }

  void close()
  {
    if (d_open) {
      mysql_close(&d_mysql);
      d_open = false;
    }
  }

  void reconnect()
  {
    logWarning("MySQL connection lost; reconnecting");
    close();
    connect();
  }

  bool isConnectionError()
  {
    const auto err = mysql_errno(&d_mysql);
    return err == CR_SERVER_GONE_ERROR || err == CR_SERVER_LOST;
  }

  std::runtime_error error(const std::string& message)
  {
    return std::runtime_error(message + ": ERROR " + std::to_string(mysql_errno(&d_mysql)) + " (" + mysql_sqlstate(&d_mysql) + "): " + mysql_error(&d_mysql));
  }

  MYSQL d_mysql{};
  bool d_open{false};
  bool d_allowReconnect{true};
  uint64_t d_generation{0};
  std::string d_host;
  std::string d_user;
  std::string d_password;
  std::string d_dbname;
  std::string d_socket;
  std::string d_defaultsFile;
  unsigned int d_port{0};
};

std::string optString(const std::vector<std::optional<std::string>>& row, size_t index)
{
  if (index >= row.size() || !row[index]) {
    return "";
  }
  return *row[index];
}

int64_t optInt(const std::vector<std::optional<std::string>>& row, size_t index, int64_t def = 0)
{
  const auto value = optString(row, index);
  if (value.empty()) {
    return def;
  }
  return std::stoll(value);
}

bool skipInvalidRecords()
{
  return getArg("invalid-records") == "skip";
}

bool handleInvalidSourceData(const std::string& message)
{
  if (skipInvalidRecords()) {
    logWarning("skipping " + message);
    return true;
  }
  throw std::runtime_error(message + "; fix the source data or set --invalid-records=skip");
}

std::optional<ZoneName> parseZoneNameFromSource(const std::string& value, const std::string& context)
{
  try {
    return ZoneName(value);
  }
  catch (const std::exception& e) {
    handleInvalidSourceData("Invalid MySQL zone name " + context + " value='" + value + "': " + e.what());
    return std::nullopt;
  }
}

class RecordDomainMap
{
public:
  void clear()
  {
    d_byRecord.clear();
  }

  void remember(uint64_t recordID, domainid_t domainID)
  {
    if (recordID == 0 || domainID == UnknownDomainID) {
      return;
    }
    d_byRecord[recordID] = domainID;
  }

  void replaceDomain(domainid_t domainID, const std::vector<MySQLRecord>& records)
  {
    forgetDomain(domainID);
    for (const auto& record : records) {
      remember(record.id, domainID);
    }
  }

  void forgetDomain(domainid_t domainID)
  {
    for (auto iter = d_byRecord.begin(); iter != d_byRecord.end();) {
      if (iter->second == domainID) {
        iter = d_byRecord.erase(iter);
      }
      else {
        ++iter;
      }
    }
  }

  std::optional<domainid_t> lookup(uint64_t recordID) const
  {
    const auto found = d_byRecord.find(recordID);
    if (found == d_byRecord.end()) {
      return std::nullopt;
    }
    return found->second;
  }

  size_t size() const
  {
    return d_byRecord.size();
  }

private:
  std::unordered_map<uint64_t, domainid_t> d_byRecord;
};

class ScopedReconnectSetting
{
public:
  ScopedReconnectSetting(MySQL& mysql, bool allow) :
    d_mysql(mysql), d_previous(mysql.allowReconnect())
  {
    d_mysql.setAllowReconnect(allow);
  }

  ~ScopedReconnectSetting()
  {
    d_mysql.setAllowReconnect(d_previous);
  }

  ScopedReconnectSetting(const ScopedReconnectSetting&) = delete;
  ScopedReconnectSetting& operator=(const ScopedReconnectSetting&) = delete;

private:
  MySQL& d_mysql;
  bool d_previous;
};

void loadRecordDomainMap(MySQL& mysql, RecordDomainMap& recordDomains)
{
  recordDomains.clear();
  mysql.forEachRow("SELECT id,domain_id FROM records", [&recordDomains](const auto& row) {
    recordDomains.remember(static_cast<uint64_t>(optInt(row, 0)), static_cast<domainid_t>(optInt(row, 1, UnknownDomainID)));
  });
  logInfo("loaded MySQL record id map records=" + std::to_string(recordDomains.size()));
}

std::string sqlString(MySQL& mysql, const std::string& value)
{
  return "'" + mysql.escape(value) + "'";
}

std::vector<ComboAddress> parsePrimaries(const std::string& master)
{
  std::vector<ComboAddress> primaries;
  std::vector<std::string> parts;
  stringtok(parts, master, ", \t");
  for (const auto& part : parts) {
    if (!part.empty()) {
      primaries.emplace_back(part, 53);
    }
  }
  return primaries;
}

std::optional<MySQLDomain> parseDomainRow(const std::vector<std::optional<std::string>>& row, const std::string& context)
{
  MySQLDomain domain;
  domain.id = static_cast<domainid_t>(optInt(row, 0));
  const auto rawName = optString(row, 1);

  try {
    const auto name = parseZoneNameFromSource(rawName, context + " id=" + std::to_string(domain.id));
    if (!name) {
      return std::nullopt;
    }
    domain.name = *name;
    domain.master = optString(row, 2);
    domain.lastCheck = static_cast<time_t>(optInt(row, 3));
    domain.kind = DomainInfo::stringToKind(optString(row, 4));
    domain.notifiedSerial = normalizeOptionalUInt32(optString(row, 5), "notified_serial", "for zone '" + domain.name.toLogString() + "'");
    domain.account = optString(row, 6);
    domain.options = optString(row, 7);
    if (!optString(row, 8).empty()) {
      const auto catalog = parseZoneNameFromSource(optString(row, 8), context + " catalog for zone '" + domain.name.toLogString() + "'");
      if (!catalog) {
        return std::nullopt;
      }
      domain.catalog = *catalog;
    }
  }
  catch (const std::exception& e) {
    handleInvalidSourceData("Invalid MySQL domain row " + context + " id=" + std::to_string(domain.id) + " name='" + rawName + "': " + e.what());
    return std::nullopt;
  }

  return domain;
}

std::optional<MySQLDomain> findDomainByName(MySQL& mysql, const ZoneName& zone)
{
  const auto rows = mysql.query("SELECT id,name,master,last_check,type,notified_serial,account,options,catalog FROM domains WHERE name=" + sqlString(mysql, zone.toStringNoDot()));
  if (rows.empty()) {
    return std::nullopt;
  }
  return parseDomainRow(rows.at(0), "from domains lookup");
}

std::vector<MySQLDomain> getDomains(MySQL& mysql)
{
  std::vector<MySQLDomain> domains;
  for (const auto& row : mysql.query("SELECT id,name,master,last_check,type,notified_serial,account,options,catalog FROM domains ORDER BY id")) {
    if (auto domain = parseDomainRow(row, "during full resync")) {
      domains.emplace_back(std::move(*domain));
    }
  }
  return domains;
}

std::vector<MySQLRecord> getRecords(MySQL& mysql, const MySQLDomain& domain)
{
  std::vector<MySQLRecord> records;
  const auto rows = mysql.query("SELECT id,name,type,content,ttl,prio,disabled,ordername,auth FROM records WHERE domain_id=" + std::to_string(domain.id) + " ORDER BY id");
  for (const auto& row : rows) {
    MySQLRecord record;
    record.id = static_cast<uint64_t>(optInt(row, 0));
    record.sourceName = optString(row, 1);
    record.sourceType = optString(row, 2);
    record.sourceContent = optString(row, 3);
    record.sourceOrdername = optString(row, 7);
    record.hasOrdername = !record.sourceOrdername.empty();
    try {
      record.rr.domain_id = domain.id;
      record.rr.qname = DNSName(record.sourceName);
      if (!record.rr.qname.isPartOf(domain.name)) {
        throw std::runtime_error("record name is outside the zone");
      }
      record.rr.auth = optInt(row, 8, 1) != 0;
      if (record.sourceType.empty()) {
        record.isENT = true;
        records.emplace_back(std::move(record));
        continue;
      }
      record.rr.qtype = QType(QType::chartocode(record.sourceType.c_str()));
      record.rr.content = record.sourceContent;
      if (record.rr.qtype == QType::SOA) {
        record.rr.content = normalizeSOAContent(domain.name, record.rr.qname, record.rr.content);
      }
      record.rr.ttl = static_cast<uint32_t>(optInt(row, 4));
      record.rr.qclass = QClass::IN;
      record.rr.disabled = optInt(row, 6) != 0;
      if (record.rr.qtype == QType::MX || record.rr.qtype == QType::SRV) {
        record.rr.content = std::to_string(optInt(row, 5)) + " " + record.rr.content;
      }
    }
    catch (const std::exception& e) {
      const auto message = "Invalid MySQL record id " + std::to_string(record.id) + " in zone '" + domain.name.toLogString() + "' name='" + record.sourceName + "' type='" + record.sourceType + "': " + e.what();
      if (handleInvalidSourceData(message)) {
        continue;
      }
    }
    records.emplace_back(std::move(record));
  }
  return records;
}

std::map<std::string, std::vector<std::string>> getMetadata(MySQL& mysql, const MySQLDomain& domain)
{
  std::map<std::string, std::vector<std::string>> metadata;
  const auto rows = mysql.query("SELECT kind,content FROM domainmetadata WHERE domain_id=" + std::to_string(domain.id) + " ORDER BY id");
  for (const auto& row : rows) {
    metadata[optString(row, 0)].push_back(optString(row, 1));
  }
  return metadata;
}

bool metadataHasOne(const std::map<std::string, std::vector<std::string>>& metadata, const std::string& kind)
{
  const auto found = metadata.find(kind);
  if (found == metadata.end()) {
    return false;
  }
  for (const auto& value : found->second) {
    if (trim(value) == "1") {
      return true;
    }
  }
  return false;
}

NSEC3Settings getNSEC3Settings(const std::map<std::string, std::vector<std::string>>& metadata, const ZoneName& zone)
{
  NSEC3Settings settings;
  const auto found = metadata.find("NSEC3PARAM");
  if (found == metadata.end()) {
    return settings;
  }
  for (const auto& value : found->second) {
    const auto trimmed = trim(value);
    if (trimmed.empty()) {
      continue;
    }
    try {
      settings.param = NSEC3PARAMRecordContent(trimmed);
      settings.present = true;
      settings.narrow = metadataHasOne(metadata, "NSEC3NARROW");
      return settings;
    }
    catch (const std::exception& e) {
      throw std::runtime_error("Invalid NSEC3PARAM metadata for zone '" + zone.toLogString() + "': " + e.what());
    }
  }
  return settings;
}

std::vector<MySQLComment> getComments(MySQL& mysql, const MySQLDomain& domain)
{
  std::vector<MySQLComment> comments;
  const auto rows = mysql.query("SELECT name,type,modified_at,account,comment FROM comments WHERE domain_id=" + std::to_string(domain.id) + " ORDER BY id");
  for (const auto& row : rows) {
    MySQLComment entry;
    const auto sourceName = optString(row, 0);
    const auto sourceType = optString(row, 1);
    try {
      entry.comment.domain_id = domain.id;
      entry.comment.qname = DNSName(sourceName);
      if (!entry.comment.qname.isPartOf(domain.name)) {
        throw std::runtime_error("comment name is outside the zone");
      }
      entry.comment.qtype = QType(QType::chartocode(sourceType.c_str()));
      entry.comment.modified_at = static_cast<time_t>(optInt(row, 2));
      entry.comment.account = optString(row, 3);
      entry.comment.content = optString(row, 4);
    }
    catch (const std::exception& e) {
      const auto message = "Invalid MySQL comment in zone '" + domain.name.toLogString() + "' name='" + sourceName + "' type='" + sourceType + "': " + e.what();
      if (handleInvalidSourceData(message)) {
        continue;
      }
    }
    comments.emplace_back(std::move(entry));
  }
  return comments;
}

std::vector<MySQLKey> getKeys(MySQL& mysql, const MySQLDomain& domain)
{
  std::vector<MySQLKey> keys;
  const auto rows = mysql.query("SELECT id,flags,active,published,content FROM cryptokeys WHERE domain_id=" + std::to_string(domain.id) + " ORDER BY id");
  for (const auto& row : rows) {
    keys.push_back({static_cast<int>(optInt(row, 0)), static_cast<unsigned int>(optInt(row, 1)), optInt(row, 2) != 0, optInt(row, 3, 1) != 0, optString(row, 4)});
  }
  return keys;
}

std::vector<DNSBackend::KeyData> getKeyData(MySQL& mysql, const MySQLDomain& domain)
{
  std::vector<DNSBackend::KeyData> keys;
  for (const auto& key : getKeys(mysql, domain)) {
    keys.push_back({key.content, static_cast<unsigned int>(key.id), key.flags, key.active, key.published});
  }
  return keys;
}

void syncTSIGKeys(MySQL& mysql, LMDBBackend& lmdb)
{
  logInfo("syncing TSIG keys");
  std::vector<TSIGKey> keys;
  for (const auto& row : mysql.query("SELECT name,algorithm,secret FROM tsigkeys ORDER BY id")) {
    const auto sourceName = optString(row, 0);
    const auto sourceAlgorithm = optString(row, 1);
    try {
      keys.push_back({DNSName(sourceName), DNSName(sourceAlgorithm), optString(row, 2)});
    }
    catch (const std::exception& e) {
      const auto message = "Invalid MySQL TSIG key name='" + sourceName + "' algorithm='" + sourceAlgorithm + "': " + e.what();
      if (handleInvalidSourceData(message)) {
        continue;
      }
    }
  }
  lmdb.replaceTSIGKeys(keys);
  logInfo("synced TSIG keys imported=" + std::to_string(keys.size()));
}

void deleteZoneIfPresent(LMDBBackend& lmdb, RecordDomainMap& recordDomains, const ZoneName& zone)
{
  DomainInfo existing;
  if (lmdb.getDomainInfo(zone, existing, false)) {
    recordDomains.forgetDomain(existing.id);
    lmdb.deleteDomain(zone);
  }
}

void syncZone(MySQL& mysql, LMDBBackend& lmdb, RecordDomainMap& recordDomains, const ZoneName& zone)
{
  const auto maybeDomain = findDomainByName(mysql, zone);
  if (!maybeDomain) {
    logInfo("zone no longer exists on MySQL primary; deleting locally zone='" + zone.toLogString() + "'");
    deleteZoneIfPresent(lmdb, recordDomains, zone);
    return;
  }
  const auto domain = *maybeDomain;
  auto records = getRecords(mysql, domain);
  auto comments = getComments(mysql, domain);
  auto metadata = getMetadata(mysql, domain);
  const auto nsec3 = getNSEC3Settings(metadata, domain.name);
  auto keys = getKeyData(mysql, domain);

  DomainInfo info;
  bool createdDomain = false;
  if (!lmdb.getDomainInfo(domain.name, info, false)) {
    lmdb.createDomain(domain.name, domain.kind, parsePrimaries(domain.master), domain.account);
    createdDomain = true;
    if (!lmdb.getDomainInfo(domain.name, info, false)) {
      throw std::runtime_error("Unable to find freshly created LMDB zone '" + domain.name.toLogString() + "'");
    }
  }

  DomainInfo replacement;
  replacement.zone = domain.name;
  replacement.kind = domain.kind;
  replacement.primaries = parsePrimaries(domain.master);
  replacement.account = domain.account;
  replacement.options = domain.options;
  replacement.catalog = domain.catalog;
  replacement.last_check = domain.lastCheck;
  replacement.notified_serial = domain.notifiedSerial;

  if (!lmdb.startTransaction(domain.name, info.id)) {
    throw std::runtime_error("Unable to start LMDB transaction for zone '" + domain.name.toLogString() + "'");
  }

  bool recordTransactionStarted = true;
  try {
    lmdb.deleteDomainCommentsInTransaction(info.id);
    std::map<DNSName, bool> nonterm;
    for (auto record : records) {
      record.rr.domain_id = info.id;
      if (record.isENT) {
        nonterm[record.rr.qname] = record.rr.auth;
        continue;
      }
      try {
        DNSName ordername;
        const bool ordernameIsNSEC3 = nsec3.present && !nsec3.narrow && record.hasOrdername;
        if (ordernameIsNSEC3) {
          ordername = DNSName(record.sourceOrdername);
        }
        lmdb.feedRecord(record.rr, ordername, ordernameIsNSEC3);
      }
      catch (const std::exception& e) {
        const auto message = "Invalid MySQL record id " + std::to_string(record.id) + " in zone '" + domain.name.toLogString() + "' name='" + record.sourceName + "' type='" + record.sourceType + "': " + e.what();
        if (handleInvalidSourceData(message)) {
          continue;
        }
      }
    }
    if (!nonterm.empty()) {
      if (nsec3.present) {
        lmdb.feedEnts3(info.id, domain.name.operator const DNSName&(), nonterm, nsec3.param, nsec3.narrow);
      }
      else {
        lmdb.feedEnts(info.id, nonterm);
      }
    }
    for (auto comment : comments) {
      comment.comment.domain_id = info.id;
      lmdb.feedComment(comment.comment);
    }
    lmdb.commitTransaction();
    recordTransactionStarted = false;

    if (!lmdb.replaceDomainInfo(replacement)) {
      throw std::runtime_error("Unable to update LMDB domain metadata for zone '" + domain.name.toLogString() + "'");
    }
    lmdb.replaceDomainMetadata(domain.name, metadata);
    lmdb.replaceDomainKeys(domain.name, keys, skipInvalidRecords());
    recordDomains.replaceDomain(domain.id, records);
  }
  catch (...) {
    if (recordTransactionStarted) {
      lmdb.abortTransaction();
    }
    if (createdDomain) {
      try {
        recordDomains.forgetDomain(domain.id);
        lmdb.deleteDomain(domain.name);
      }
      catch (const std::exception& e) {
        logWarning("unable to clean up newly created LMDB zone after failed sync zone='" + domain.name.toLogString() + "': " + e.what());
      }
    }
    throw;
  }
}

BinlogPosition fullResyncOnce(MySQL& mysql, LMDBBackend& lmdb, RecordDomainMap& recordDomains, const std::string& reason)
{
  bool locked = false;
  bool transaction = false;
  uint64_t snapshotGeneration = 0;
  std::unique_ptr<ScopedReconnectSetting> snapshotReconnect;
  BinlogPosition position;

  logInfo("full resync started reason='" + reason + "'");
  try {
    logInfo("full resync acquiring MySQL read lock");
    mysql.executeTransactionQuery("FLUSH TABLES WITH READ LOCK");
    locked = true;
    position = mysql.masterStatus();
    logInfo("full resync snapshot position=" + describePosition(position));
    mysql.executeTransactionQuery("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    mysql.executeTransactionQuery("START TRANSACTION WITH CONSISTENT SNAPSHOT");
    transaction = true;
    snapshotGeneration = mysql.connectionGeneration();
    snapshotReconnect = std::make_unique<ScopedReconnectSetting>(mysql, false);
    mysql.executeTransactionQuery("UNLOCK TABLES");
    locked = false;
    logInfo("full resync released MySQL read lock; reading from consistent snapshot");
  }
  catch (...) {
    if (locked) {
      mysql.executeTransactionQuery("UNLOCK TABLES");
    }
    throw;
  }

  std::set<ZoneName> mysqlZones;
  try {
    recordDomains.clear();
    for (const auto& domain : getDomains(mysql)) {
      mysqlZones.insert(domain.name);
    }

    std::vector<DomainInfo> lmdbDomains;
    lmdb.getAllDomains(&lmdbDomains, false, true);
    size_t removedZones = 0;
    for (const auto& domain : lmdbDomains) {
      if (mysqlZones.count(domain.zone) == 0) {
        recordDomains.forgetDomain(domain.id);
        lmdb.deleteDomain(domain.zone);
        ++removedZones;
      }
    }

    logInfo("full resync applying zones mysql_zones=" + std::to_string(mysqlZones.size()) + " local_zones=" + std::to_string(lmdbDomains.size()) + " removed_stale=" + std::to_string(removedZones));
    size_t syncedZones = 0;
    for (const auto& zone : mysqlZones) {
      syncZone(mysql, lmdb, recordDomains, zone);
      ++syncedZones;
      if (syncedZones % 1000 == 0) {
        logInfo("full resync progress synced_zones=" + std::to_string(syncedZones) + "/" + std::to_string(mysqlZones.size()));
      }
    }
    syncTSIGKeys(mysql, lmdb);
    mysql.executeTransactionQuery("COMMIT");
    transaction = false;
    snapshotReconnect.reset();
    if (mysql.connectionGeneration() != snapshotGeneration) {
      throw SnapshotRestartException("MySQL connection changed while reading consistent snapshot");
    }
    logInfo("full resync completed synced_zones=" + std::to_string(syncedZones) + " snapshot_position=" + describePosition(position));
    trimAllocator("full resync completed");
  }
  catch (const SnapshotRestartException&) {
    snapshotReconnect.reset();
    throw;
  }
  catch (...) {
    snapshotReconnect.reset();
    if (transaction) {
      try {
        mysql.executeTransactionQuery("ROLLBACK");
      }
      catch (const std::exception& e) {
        logWarning(std::string("unable to roll back failed snapshot transaction: ") + e.what());
      }
    }
    throw;
  }

  return position;
}

BinlogPosition fullResync(MySQL& mysql, LMDBBackend& lmdb, RecordDomainMap& recordDomains, const std::string& reason)
{
  for (unsigned int attempt = 1; attempt <= 5; ++attempt) {
    try {
      return fullResyncOnce(mysql, lmdb, recordDomains, reason);
    }
    catch (const SnapshotRestartException& e) {
      logWarning("full resync snapshot was lost; restarting attempt=" + std::to_string(attempt) + " reason='" + oneLine(e.what()) + "'");
      recordDomains.clear();
      mysql.resetConnection();
    }
  }
  throw std::runtime_error("Full resync snapshot was lost repeatedly; giving up after 5 attempts");
}

std::optional<BinlogPosition> loadState()
{
  const auto stateFile = resolvedStateFile();
  std::ifstream input(stateFile);
  if (!input) {
    return std::nullopt;
  }

  BinlogPosition pos;
  std::string line;
  while (std::getline(input, line)) {
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    const auto key = line.substr(0, equals);
    const auto value = line.substr(equals + 1);
    if (key == "binlog") {
      pos.file = value;
    }
    else if (key == "position") {
      pos.pos = static_cast<uint64_t>(std::stoull(value));
    }
  }

  if (pos.file.empty()) {
    return std::nullopt;
  }
  logInfo("loaded replication state file='" + stateFile + "' position=" + describePosition(pos));
  return pos;
}

void saveState(const BinlogPosition& pos)
{
  const auto stateFile = resolvedStateFile();
  const auto tmp = stateFile + ".tmp";
  {
    std::ofstream output(tmp);
    if (!output) {
      throw std::runtime_error("Unable to write state file '" + tmp + "'");
    }
    output << "binlog=" << pos.file << "\n";
    output << "position=" << pos.pos << "\n";
    if (!output) {
      throw std::runtime_error("Unable to write complete state file '" + tmp + "'");
    }
  }

  int tmpfd = open(tmp.c_str(), O_RDONLY);
  if (tmpfd < 0) {
    throw std::runtime_error("Unable to open state file '" + tmp + "' for sync: " + stringerror());
  }
  if (fsync(tmpfd) != 0) {
    const auto err = stringerror();
    close(tmpfd);
    throw std::runtime_error("Unable to sync state file '" + tmp + "': " + err);
  }
  close(tmpfd);

  if (rename(tmp.c_str(), stateFile.c_str()) != 0) {
    throw std::runtime_error("Unable to rename state file '" + tmp + "': " + stringerror());
  }

  const auto directory = dirnameOf(stateFile);
  int dirfd = open(directory.c_str(), O_RDONLY | O_DIRECTORY);
  if (dirfd >= 0) {
    if (fsync(dirfd) != 0) {
      const auto err = stringerror();
      close(dirfd);
      throw std::runtime_error("Unable to sync state file directory '" + directory + "': " + err);
    }
    close(dirfd);
  }
  logInfo("saved replication state file='" + stateFile + "' position=" + describePosition(pos));
}

void saveAppliedState(LMDBBackend& lmdb, const BinlogPosition& pos)
{
  lmdb.sync();
  saveState(pos);
}

void validateBinlogSettings(MySQL& mysql)
{
  const auto rows = mysql.query("SELECT @@binlog_format, @@binlog_row_image");
  if (rows.empty() || rows.at(0).size() < 2 || !rows.at(0).at(0) || !rows.at(0).at(1)) {
    throw std::runtime_error("Unable to read MySQL binlog settings");
  }

  const auto binlogFormat = toUpperASCII(*rows.at(0).at(0));
  const auto rowImage = toUpperASCII(*rows.at(0).at(1));
  if (rowImage != "FULL") {
    throw std::runtime_error("MySQL @@binlog_row_image must be FULL for pdns-mysql2lmdb; current value is '" + rowImage + "'");
  }
  logInfo("validated MySQL binlog settings format='" + binlogFormat + "' row_image='" + rowImage + "'");
}

std::vector<std::string> mysqlbinlogArguments(const BinlogPosition& pos)
{
  std::vector<std::string> args;
  args.push_back(getArg("mysqlbinlog"));
  if (!getArg("mysql-defaults-file").empty()) {
    args.push_back("--defaults-extra-file=" + getArg("mysql-defaults-file"));
  }
  args.push_back("--read-from-remote-server");
  if (!getBoolArg("once")) {
    args.push_back("--stop-never");
  }
  args.push_back("--base64-output=DECODE-ROWS");
  args.push_back("-vv");
  if (!usingDefaultsFile() || argDiffersFromDefault("mysql-host")) {
    args.push_back("--host=" + getArg("mysql-host"));
  }
  if (!usingDefaultsFile() || argDiffersFromDefault("mysql-port")) {
    args.push_back("--port=" + std::to_string(getPort()));
  }
  if (!getArg("mysql-user").empty() && (!usingDefaultsFile() || argDiffersFromDefault("mysql-user"))) {
    args.push_back("--user=" + getArg("mysql-user"));
  }
  if (!getArg("mysql-socket").empty() && (!usingDefaultsFile() || argDiffersFromDefault("mysql-socket"))) {
    args.push_back("--socket=" + getArg("mysql-socket"));
  }
  args.push_back("--start-position=" + std::to_string(pos.pos));
  args.push_back(pos.file);
  return args;
}

struct ChildPipe
{
  FILE* stream{nullptr};
  pid_t pid{-1};

  int close(bool terminateChild = false)
  {
    int status = -1;
    if (terminateChild && pid > 0) {
      kill(pid, SIGTERM);
    }
    if (stream != nullptr) {
      fclose(stream);
      stream = nullptr;
    }
    if (pid > 0) {
      if (terminateChild) {
        for (unsigned int tries = 0; tries < 40; ++tries) {
          const auto waited = waitpid(pid, &status, WNOHANG);
          if (waited == pid) {
            pid = -1;
            return status;
          }
          if (waited < 0) {
            if (errno == EINTR) {
              continue;
            }
            pid = -1;
            return -1;
          }
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        kill(pid, SIGKILL);
      }
      while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
          pid = -1;
          return -1;
        }
      }
      pid = -1;
    }
    return status;
  }
};

ChildPipe startMysqlbinlog(const BinlogPosition& pos)
{
  int fds[2];
  if (pipe(fds) != 0) {
    throw std::runtime_error("Unable to create mysqlbinlog pipe: " + stringerror());
  }

  auto args = mysqlbinlogArguments(pos);
  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    throw std::runtime_error("Unable to fork mysqlbinlog: " + stringerror());
  }

  if (pid == 0) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0) {
      _exit(127);
    }
    close(fds[1]);

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) {
      argv.push_back(arg.data());
    }
    argv.push_back(nullptr);
    execvp(argv.at(0), argv.data());
    _exit(127);
  }

  close(fds[1]);
  FILE* stream = fdopen(fds[0], "r");
  if (stream == nullptr) {
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    throw std::runtime_error("Unable to open mysqlbinlog pipe stream: " + stringerror());
  }

  return {stream, pid};
}

std::optional<std::string> parseRowStringValue(const std::string& line)
{
  const auto equals = line.find('=');
  if (equals == std::string::npos) {
    return std::nullopt;
  }
  auto value = trim(line.substr(equals + 1));
  if (value.empty()) {
    return value;
  }

  if (value.front() == '\'') {
    bool escaped = false;
    for (size_t pos = 1; pos < value.size(); ++pos) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (value.at(pos) == '\\') {
        escaped = true;
        continue;
      }
      if (value.at(pos) == '\'') {
        return value.substr(1, pos - 1);
      }
    }
  }

  const auto comment = value.find("/*");
  if (comment != std::string::npos) {
    value = trim(value.substr(0, comment));
  }
  return value;
}

std::optional<int64_t> parseRowIntValue(const std::string& line)
{
  const auto value = parseRowStringValue(line);
  if (!value || value->empty() || *value == "NULL") {
    return std::nullopt;
  }
  char* end = nullptr;
  errno = 0;
  const auto parsed = std::strtoll(value->c_str(), &end, 10);
  if (errno != 0 || end == value->c_str()) {
    return std::nullopt;
  }
  return parsed;
}

std::optional<uint64_t> parseMysqlbinlogAtPosition(const std::string& line)
{
  if (line.rfind("# at ", 0) != 0) {
    return std::nullopt;
  }
  char* end = nullptr;
  errno = 0;
  const auto parsed = std::strtoull(line.c_str() + 5, &end, 10);
  if (errno != 0 || end == line.c_str() + 5) {
    return std::nullopt;
  }
  return parsed;
}

std::optional<uint64_t> parseMysqlbinlogEndPosition(const std::string& line)
{
  static const std::regex endLogPosPattern(R"(\bend_log_pos\s+([0-9]+)\b)");
  std::smatch match;
  if (!std::regex_search(line, match, endLogPosPattern)) {
    return std::nullopt;
  }
  return static_cast<uint64_t>(std::stoull(match[1].str()));
}

std::optional<std::string> parseMysqlbinlogRotateFile(const std::string& line)
{
  if (line.rfind("#", 0) != 0) {
    return std::nullopt;
  }
  static const std::regex rotatePattern(R"(\bRotate to (\S+))");
  std::smatch match;
  if (!std::regex_search(line, match, rotatePattern)) {
    return std::nullopt;
  }
  return match[1].str();
}

std::optional<std::pair<std::string, std::string>> parseRowEventDatabaseTable(const std::string& line)
{
  std::vector<std::string> parts;
  size_t pos = 0;
  while (true) {
    const auto start = line.find('`', pos);
    if (start == std::string::npos) {
      break;
    }
    const auto end = line.find('`', start + 1);
    if (end == std::string::npos) {
      break;
    }
    parts.push_back(line.substr(start + 1, end - start - 1));
    pos = end + 1;
  }
  if (parts.size() < 2) {
    return std::nullopt;
  }
  return std::make_pair(parts.at(0), parts.at(1));
}

std::optional<ZoneName> getZoneById(MySQL& mysql, domainid_t domainId)
{
  const auto rows = mysql.query("SELECT name FROM domains WHERE id=" + std::to_string(domainId));
  if (rows.empty() || !rows.at(0).at(0)) {
    return std::nullopt;
  }
  return ZoneName(*rows.at(0).at(0));
}

std::string joinIds(const std::set<uint64_t>& ids)
{
  std::string joined;
  for (const auto id : ids) {
    if (!joined.empty()) {
      joined += ',';
    }
    joined += std::to_string(id);
  }
  return joined;
}

std::set<ZoneName> getZonesByRowIds(MySQL& mysql, const std::string& table, const std::set<uint64_t>& ids)
{
  std::set<ZoneName> zones;
  if (ids.empty()) {
    return zones;
  }

  const auto rows = mysql.query("SELECT DISTINCT d.name FROM domains d JOIN " + table + " t ON t.domain_id=d.id WHERE t.id IN (" + joinIds(ids) + ")");
  for (const auto& row : rows) {
    if (row.at(0)) {
      zones.insert(ZoneName(*row.at(0)));
    }
  }
  return zones;
}

void applyChangedZones(MySQL& mysql, LMDBBackend& lmdb, RecordDomainMap& recordDomains, const std::set<ZoneName>& zones, const std::set<ZoneName>& deletedZones, bool syncTSIG)
{
  logInfo("applying incremental changes changed_zones=" + summarizeZones(zones) + " deleted_zones=" + summarizeZones(deletedZones) + " sync_tsig=" + std::string(syncTSIG ? "yes" : "no"));
  for (const auto& zone : deletedZones) {
    deleteZoneIfPresent(lmdb, recordDomains, zone);
  }
  for (const auto& zone : zones) {
    syncZone(mysql, lmdb, recordDomains, zone);
  }
  if (syncTSIG) {
    syncTSIGKeys(mysql, lmdb);
  }
  logInfo("applied incremental changes");
}

struct StatementChange
{
  std::set<ZoneName> changedZones;
  std::set<ZoneName> deletedZones;
  bool syncTSIG{false};
  bool needsFullResync{false};
};

struct StatementTable
{
  std::string database;
  std::string table;
};

std::optional<StatementTable> extractStatementTable(const std::string& sql)
{
  static const std::vector<std::regex> tablePatterns{
    std::regex(R"(^\s*(?:insert|replace)\s+(?:ignore\s+)?into\s+(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
    std::regex(R"(^\s*update\s+(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
    std::regex(R"(^\s*delete\s+from\s+(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
    std::regex(R"(^\s*truncate\s+(?:table\s+)?(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
    std::regex(R"(^\s*alter\s+(?:table\s+)?(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
    std::regex(R"(^\s*drop\s+(?:table\s+)?(?:if\s+exists\s+)?(?:`?([[:alnum:]_]+)`?\.)?`?([[:alnum:]_]+)`?)", std::regex::icase),
  };

  std::smatch match;
  for (const auto& pattern : tablePatterns) {
    if (std::regex_search(sql, match, pattern)) {
      StatementTable table;
      if (match[1].matched) {
        table.database = match[1].str();
      }
      table.table = match[2].str();
      return table;
    }
  }
  return std::nullopt;
}

bool statementUsesRelevantDatabase(const std::optional<StatementTable>& table, const std::string& currentDatabase)
{
  const auto expected = toLowerASCII(getArg("mysql-dbname"));
  if (table && !table->database.empty()) {
    return toLowerASCII(table->database) == expected;
  }
  return toLowerASCII(currentDatabase) == expected;
}

std::string normalizeSQLIdentifier(std::string value)
{
  value = trim(value);
  if (value.size() >= 2 && value.front() == '`' && value.back() == '`') {
    value = value.substr(1, value.size() - 2);
  }
  return toLowerASCII(value);
}

std::vector<std::string> splitSQLList(const std::string& value)
{
  std::vector<std::string> entries;
  std::string entry;
  bool inString = false;
  bool inBacktick = false;
  bool escaped = false;
  int depth = 0;

  for (const auto chr : value) {
    if (escaped) {
      entry.push_back(chr);
      escaped = false;
      continue;
    }

    if (inString && chr == '\\') {
      entry.push_back(chr);
      escaped = true;
      continue;
    }

    if (!inBacktick && chr == '\'') {
      inString = !inString;
      entry.push_back(chr);
      continue;
    }

    if (!inString && chr == '`') {
      inBacktick = !inBacktick;
      entry.push_back(chr);
      continue;
    }

    if (!inString && !inBacktick) {
      if (chr == '(') {
        ++depth;
      }
      else if (chr == ')' && depth > 0) {
        --depth;
      }
      else if (chr == ',' && depth == 0) {
        entries.push_back(trim(entry));
        entry.clear();
        continue;
      }
    }

    entry.push_back(chr);
  }

  if (!entry.empty()) {
    entries.push_back(trim(entry));
  }
  return entries;
}

std::vector<std::string> extractSQLValueTuples(const std::string& values)
{
  std::vector<std::string> tuples;
  std::string tuple;
  bool inString = false;
  bool inBacktick = false;
  bool escaped = false;
  int depth = 0;

  for (const auto chr : values) {
    if (escaped) {
      if (depth > 0) {
        tuple.push_back(chr);
      }
      escaped = false;
      continue;
    }

    if (inString && chr == '\\') {
      if (depth > 0) {
        tuple.push_back(chr);
      }
      escaped = true;
      continue;
    }

    if (!inBacktick && chr == '\'') {
      inString = !inString;
      if (depth > 0) {
        tuple.push_back(chr);
      }
      continue;
    }

    if (!inString && chr == '`') {
      inBacktick = !inBacktick;
      if (depth > 0) {
        tuple.push_back(chr);
      }
      continue;
    }

    if (!inString && !inBacktick) {
      if (chr == '(') {
        if (depth++ == 0) {
          tuple.clear();
          continue;
        }
      }
      else if (chr == ')' && depth > 0) {
        if (--depth == 0) {
          tuples.push_back(trim(tuple));
          tuple.clear();
          continue;
        }
      }
    }

    if (depth > 0) {
      tuple.push_back(chr);
    }
  }

  return tuples;
}

std::set<domainid_t> extractDomainIdsFromInsertValues(const std::string& sql)
{
  std::set<domainid_t> ids;
  static const std::regex insertValuesPattern(R"(^\s*(?:insert|replace)\s+(?:ignore\s+)?into\s+(?:`?[[:alnum:]_]+`?\.)?`?[[:alnum:]_]+`?\s*\(([^)]*)\)\s*values\s*([\s\S]*)$)", std::regex::icase);

  std::smatch match;
  if (!std::regex_search(sql, match, insertValuesPattern)) {
    return ids;
  }

  const auto columns = splitSQLList(match[1].str());
  size_t domainIDColumn = columns.size();
  for (size_t n = 0; n < columns.size(); ++n) {
    if (normalizeSQLIdentifier(columns[n]) == "domain_id") {
      domainIDColumn = n;
      break;
    }
  }
  if (domainIDColumn == columns.size()) {
    return ids;
  }

  for (const auto& tuple : extractSQLValueTuples(match[2].str())) {
    const auto values = splitSQLList(tuple);
    if (domainIDColumn >= values.size()) {
      continue;
    }
    const auto value = trim(values[domainIDColumn]);
    if (!value.empty() && std::isdigit(static_cast<unsigned char>(value.front()))) {
      ids.insert(static_cast<domainid_t>(std::stoll(value)));
    }
  }

  return ids;
}

std::string unquoteSQLString(std::string value)
{
  value = trim(value);
  if (value.size() < 2 || value.front() != '\'' || value.back() != '\'') {
    return value;
  }

  std::string output;
  output.reserve(value.size() - 2);
  bool escaped = false;
  for (auto iter = value.begin() + 1; iter != value.end() - 1; ++iter) {
    const auto chr = *iter;
    if (escaped) {
      output.push_back(chr);
      escaped = false;
      continue;
    }
    if (chr == '\\') {
      escaped = true;
      continue;
    }
    if (chr == '\'' && iter + 1 != value.end() - 1 && *(iter + 1) == '\'') {
      output.push_back(chr);
      ++iter;
      continue;
    }
    output.push_back(chr);
  }
  return output;
}

std::vector<std::string> extractInsertColumnValues(const std::string& sql, const std::string& columnName)
{
  std::vector<std::string> values;
  static const std::regex insertValuesPattern(R"(^\s*(?:insert|replace)\s+(?:ignore\s+)?into\s+(?:`?[[:alnum:]_]+`?\.)?`?[[:alnum:]_]+`?\s*\(([^)]*)\)\s*values\s*([\s\S]*)$)", std::regex::icase);

  std::smatch match;
  if (!std::regex_search(sql, match, insertValuesPattern)) {
    return values;
  }

  const auto columns = splitSQLList(match[1].str());
  size_t valueColumn = columns.size();
  for (size_t n = 0; n < columns.size(); ++n) {
    if (normalizeSQLIdentifier(columns[n]) == columnName) {
      valueColumn = n;
      break;
    }
  }
  if (valueColumn == columns.size()) {
    return values;
  }

  for (const auto& tuple : extractSQLValueTuples(match[2].str())) {
    const auto tupleValues = splitSQLList(tuple);
    if (valueColumn < tupleValues.size()) {
      values.push_back(unquoteSQLString(tupleValues[valueColumn]));
    }
  }
  return values;
}

std::set<domainid_t> extractDomainIdsFromStatement(const std::string& sql)
{
  auto ids = extractDomainIdsFromInsertValues(sql);
  static const std::regex domainIdPattern(R"((^|[^[:alnum:]_])(?:`?[[:alnum:]_]+`?\s*\.\s*)?`?domain_id`?\s*(?:=|in\s*\()\s*([0-9][0-9,\s]*)\)?)", std::regex::icase);
  auto begin = std::sregex_iterator(sql.begin(), sql.end(), domainIdPattern);
  auto end = std::sregex_iterator();
  for (auto iter = begin; iter != end; ++iter) {
    std::vector<std::string> parts;
    stringtok(parts, (*iter)[2].str(), ", ");
    for (const auto& part : parts) {
      if (!part.empty()) {
        ids.insert(static_cast<domainid_t>(std::stoll(part)));
      }
    }
  }
  return ids;
}

std::set<uint64_t> extractRowIdsFromStatement(const std::string& sql)
{
  std::set<uint64_t> ids;
  static const std::regex rowIdPattern(R"((^|[^[:alnum:]_])(?:`?[[:alnum:]_]+`?\s*\.\s*)?`?id`?\s*(?:=|in\s*\()\s*([0-9][0-9,\s]*)\)?)", std::regex::icase);
  auto begin = std::sregex_iterator(sql.begin(), sql.end(), rowIdPattern);
  auto end = std::sregex_iterator();
  for (auto iter = begin; iter != end; ++iter) {
    std::vector<std::string> parts;
    stringtok(parts, (*iter)[2].str(), ", ");
    for (const auto& part : parts) {
      if (!part.empty()) {
        ids.insert(std::stoull(part));
      }
    }
  }
  return ids;
}

std::optional<ZoneName> parseZoneNameFromStatementValue(const std::string& value, bool& invalidName)
{
  try {
    return ZoneName(value);
  }
  catch (const std::exception& e) {
    invalidName = true;
    logWarning("binlog statement contains invalid zone name value='" + value + "': " + e.what());
    return std::nullopt;
  }
}

std::set<ZoneName> extractDomainNamesFromStatement(const std::string& sql, bool& invalidName)
{
  std::set<ZoneName> names;
  static const std::regex namePattern(R"(\bname\b\s*=\s*'([^']+)')", std::regex::icase);
  auto begin = std::sregex_iterator(sql.begin(), sql.end(), namePattern);
  auto end = std::sregex_iterator();
  for (auto iter = begin; iter != end; ++iter) {
    if (auto name = parseZoneNameFromStatementValue((*iter)[1].str(), invalidName)) {
      names.insert(*name);
    }
  }
  return names;
}

bool statementHasUnsafeNamePredicate(const std::string& sql)
{
  static const std::regex unsafeNamePredicate(R"(\bname\b\s*(?:not\s+)?(?:like|regexp|rlike)\b|\bname\b\s*(?:<>|!=|<|>|is\b))", std::regex::icase);
  return std::regex_search(sql, unsafeNamePredicate);
}

bool startsWithSQLVerb(const std::string& sql, const std::string& verb)
{
  const auto lower = toLowerASCII(trim(sql));
  return lower.rfind(verb, 0) == 0;
}

std::optional<std::string> extractWhereClause(const std::string& sql)
{
  static const std::regex wherePattern(R"(\bwhere\b([\s\S]*)$)", std::regex::icase);
  std::smatch match;
  if (!std::regex_search(sql, match, wherePattern)) {
    return std::nullopt;
  }
  return match[1].str();
}

bool updateStatementAssignsName(const std::string& sql)
{
  static const std::regex updatePattern(R"(^\s*update\s+(?:`?[[:alnum:]_]+`?\.)?`?domains`?\s+set\s+([\s\S]*?)(?:\bwhere\b|$))", std::regex::icase);
  static const std::regex namePattern(R"(\bname\b\s*=)", std::regex::icase);
  std::smatch updateMatch;
  if (!std::regex_search(sql, updateMatch, updatePattern)) {
    return false;
  }
  return std::regex_search(updateMatch[1].str(), namePattern);
}

bool updateStatementAssignsDomainID(const std::string& sql)
{
  static const std::regex updatePattern(R"(^\s*update\s+(?:`?[[:alnum:]_]+`?\.)?`?[[:alnum:]_]+`?\s+set\s+([\s\S]*?)(?:\bwhere\b|$))", std::regex::icase);
  static const std::regex domainIDPattern(R"(\bdomain_id\b\s*=)", std::regex::icase);
  std::smatch updateMatch;
  if (!std::regex_search(sql, updateMatch, updatePattern)) {
    return false;
  }
  return std::regex_search(updateMatch[1].str(), domainIDPattern);
}

std::optional<std::pair<ZoneName, ZoneName>> extractDomainRenameFromStatement(const std::string& sql, bool& invalidName)
{
  static const std::regex updatePattern(R"(^\s*update\s+(?:`?[[:alnum:]_]+`?\.)?`?domains`?\s+set\s+([\s\S]*?)\bwhere\b([\s\S]*)$)", std::regex::icase);
  std::smatch updateMatch;
  if (!std::regex_search(sql, updateMatch, updatePattern)) {
    return std::nullopt;
  }

  const auto setPart = updateMatch[1].str();
  const auto wherePart = updateMatch[2].str();
  const auto setNames = extractDomainNamesFromStatement(setPart, invalidName);
  const auto whereNames = extractDomainNamesFromStatement(wherePart, invalidName);
  if (setNames.size() != 1 || whereNames.size() != 1) {
    return std::nullopt;
  }
  return std::make_pair(*whereNames.begin(), *setNames.begin());
}

bool statementTouchesPowerDNSTable(const std::string& sql, const std::string& table)
{
  if (table == "domains" || table == "records" || table == "comments" || table == "domainmetadata" || table == "cryptokeys" || table == "tsigkeys") {
    return true;
  }

  const auto lower = toLowerASCII(sql);
  return lower.find(" domains") != std::string::npos ||
         lower.find("`domains`") != std::string::npos ||
         lower.find(" records") != std::string::npos ||
         lower.find("`records`") != std::string::npos ||
         lower.find(" comments") != std::string::npos ||
         lower.find("`comments`") != std::string::npos ||
         lower.find(" domainmetadata") != std::string::npos ||
         lower.find("`domainmetadata`") != std::string::npos ||
         lower.find(" cryptokeys") != std::string::npos ||
         lower.find("`cryptokeys`") != std::string::npos ||
         lower.find(" tsigkeys") != std::string::npos ||
         lower.find("`tsigkeys`") != std::string::npos;
}

StatementChange analyzeStatement(MySQL& mysql, const RecordDomainMap& recordDomains, const std::string& sql)
{
  StatementChange change;
  const auto maybeTable = extractStatementTable(sql);
  const auto table = maybeTable ? toLowerASCII(maybeTable->table) : "";
  if (!maybeTable && !statementTouchesPowerDNSTable(sql, "")) {
    return change;
  }

  if (!statementTouchesPowerDNSTable(sql, table)) {
    return change;
  }

  if (table == "tsigkeys") {
    change.syncTSIG = true;
    return change;
  }

  if (table == "domains") {
    bool invalidStatementName = false;
    if (startsWithSQLVerb(sql, "update")) {
      if (const auto rename = extractDomainRenameFromStatement(sql, invalidStatementName)) {
        if (rename->first != rename->second) {
          change.deletedZones.insert(rename->first);
        }
        change.changedZones.insert(rename->second);
        return change;
      }
      if (invalidStatementName || updateStatementAssignsName(sql) || statementHasUnsafeNamePredicate(sql)) {
        change.needsFullResync = true;
        return change;
      }
    }
    for (const auto& name : extractInsertColumnValues(sql, "name")) {
      if (!name.empty() && toLowerASCII(name) != "null") {
        if (auto zone = parseZoneNameFromStatementValue(name, invalidStatementName)) {
          change.changedZones.insert(*zone);
        }
      }
    }
    if (invalidStatementName || statementHasUnsafeNamePredicate(sql)) {
      change.needsFullResync = true;
      return change;
    }
    if (!change.changedZones.empty()) {
      return change;
    }
    const auto zones = extractDomainNamesFromStatement(sql, invalidStatementName);
    if (invalidStatementName) {
      change.needsFullResync = true;
      return change;
    }
    if (!zones.empty()) {
      if (startsWithSQLVerb(sql, "delete") || startsWithSQLVerb(sql, "truncate")) {
        change.deletedZones.insert(zones.begin(), zones.end());
      }
      else {
        change.changedZones.insert(zones.begin(), zones.end());
      }
      return change;
    }
    if (!startsWithSQLVerb(sql, "delete") && !startsWithSQLVerb(sql, "truncate")) {
      for (const auto id : extractRowIdsFromStatement(sql)) {
        if (const auto zone = getZoneById(mysql, static_cast<domainid_t>(id))) {
          change.changedZones.insert(*zone);
        }
      }
      if (!change.changedZones.empty()) {
        return change;
      }
    }
    change.needsFullResync = true;
    return change;
  }

  const auto lower = toLowerASCII(trim(sql));
  const auto domainIDs = extractDomainIdsFromStatement(sql);
  const auto rowIDs = extractRowIdsFromStatement(sql);
  const auto whereClause = extractWhereClause(sql);
  const auto whereDomainIDs = whereClause ? extractDomainIdsFromStatement(*whereClause) : std::set<domainid_t>{};
  const bool unsafeNamePredicate = statementHasUnsafeNamePredicate(sql);

  for (const auto id : domainIDs) {
    if (const auto zone = getZoneById(mysql, id)) {
      change.changedZones.insert(*zone);
    }
  }

  if (unsafeNamePredicate) {
    change.needsFullResync = true;
    return change;
  }

  if (table == "records" || table == "comments" || table == "domainmetadata" || table == "cryptokeys") {
    if (lower.find("truncate") != 0) {
      if ((lower.find("update") == 0 || lower.find("delete") == 0) && rowIDs.empty() && whereDomainIDs.empty()) {
        change.needsFullResync = true;
        return change;
      }
      const auto zones = getZonesByRowIds(mysql, table, rowIDs);
      change.changedZones.insert(zones.begin(), zones.end());
      if (table != "records" && lower.find("update") == 0 && updateStatementAssignsDomainID(sql) && whereDomainIDs.empty()) {
        change.needsFullResync = true;
        return change;
      }
      if (table == "records" && (lower.find("delete") == 0 || lower.find("update") == 0)) {
        for (const auto rowID : rowIDs) {
          if (const auto domainID = recordDomains.lookup(rowID)) {
            if (const auto zone = getZoneById(mysql, *domainID)) {
              change.changedZones.insert(*zone);
            }
          }
        }
      }
    }
  }

  if (!change.changedZones.empty()) {
    return change;
  }

  change.needsFullResync = true;
  return change;
}

bool lineIndicatesMissingBinlog(const std::string& line)
{
  return line.find("Could not find first log file name") != std::string::npos ||
         line.find("File not found") != std::string::npos ||
         line.find("not found in binary log index") != std::string::npos ||
         line.find("start replication from position > file size") != std::string::npos;
}

void followBinlog(MySQL& mysql, LMDBBackend& lmdb, RecordDomainMap& recordDomains, BinlogPosition pos)
{
  logInfo("incremental mode starting position=" + describePosition(pos));
  BinlogPosition appliedPos = pos;
  while (true) {
    logInfo("starting mysqlbinlog stream position=" + describePosition(pos) + " mode=" + std::string(getBoolArg("once") ? "once" : "continuous"));
    auto child = startMysqlbinlog(pos);

    std::set<ZoneName> changedZones;
    std::set<ZoneName> deletedZones;
    bool syncTSIG = false;
    std::string table;
    domainid_t domainRowId = UnknownDomainID;
    bool domainRowIdSet = false;
    std::optional<ZoneName> oldDomainRowName;
    std::optional<ZoneName> newDomainRowName;
    bool deleteDomainRow = false;
    bool domainValuesAreNew = false;
    std::string currentDatabase = getArg("mysql-dbname");
    std::string statementSql;
    std::deque<std::string> recentMysqlbinlogOutput;
    std::optional<std::string> pendingRotateFile;
    uint64_t currentEventEndPos = 0;
    bool haveCurrentEventEndPos = false;

    bool missingBinlog = false;
    bool forceFullResync = false;
    std::string line;
    while (readPipeLine(child.stream, line)) {
      line = trim(line);
      if (line.empty()) {
        continue;
      }
      rememberOutputLine(recentMysqlbinlogOutput, line);

      if (lineIndicatesMissingBinlog(line)) {
        missingBinlog = true;
        logWarning("mysqlbinlog reported missing/unreadable binlog: " + line);
      }

      if (const auto atPos = parseMysqlbinlogAtPosition(line)) {
        if (pendingRotateFile && *atPos <= 4) {
          pos.file = *pendingRotateFile;
          pos.pos = *atPos;
          currentEventEndPos = 0;
          haveCurrentEventEndPos = false;
          pendingRotateFile.reset();
          logInfo("binlog rotated current_position=" + describePosition(pos));
        }
        continue;
      }

      if (const auto endPos = parseMysqlbinlogEndPosition(line)) {
        if (pendingRotateFile && *endPos != 0 && *endPos < pos.pos) {
          pos.file = *pendingRotateFile;
          pendingRotateFile.reset();
          logInfo("binlog rotated current_position=" + pos.file + ":" + std::to_string(*endPos));
        }
        currentEventEndPos = *endPos;
        haveCurrentEventEndPos = true;
        if (*endPos != 0) {
          pos.pos = *endPos;
        }
      }

      if (const auto rotateFile = parseMysqlbinlogRotateFile(line)) {
        pendingRotateFile = *rotateFile;
        logInfo("binlog rotate pending next_file=" + *rotateFile);
        continue;
      }

      if (line.rfind("use `", 0) == 0) {
        const auto end = line.find('`', 5);
        if (end != std::string::npos) {
          currentDatabase = line.substr(5, end - 5);
        }
        continue;
      }

      const bool rowCommitLine = line == "COMMIT/*!*/;" || line == "COMMIT";
      if (!rowCommitLine && line.rfind("#", 0) != 0 && line.rfind("###", 0) != 0) {
        auto statementLine = line;
        const bool endsStatement = statementLine == "/*!*/;" || (statementLine.size() >= 6 && statementLine.compare(statementLine.size() - 6, 6, "/*!*/;") == 0);
        if (endsStatement) {
          const auto marker = statementLine.find("/*!*/;");
          statementLine = marker == std::string::npos ? "" : statementLine.substr(0, marker);
        }

        const bool skipStatementLine = statementSql.empty() &&
                                       (statementLine == "BEGIN" ||
                                        statementLine == "COMMIT" ||
                                        statementLine.rfind("SET ", 0) == 0 ||
                                        statementLine.rfind("SET @@", 0) == 0);
        if (!statementLine.empty() &&
            !skipStatementLine) {
          if (!statementSql.empty()) {
            statementSql += '\n';
          }
          statementSql += statementLine;
        }

        if (endsStatement && !statementSql.empty()) {
          const auto statementTable = extractStatementTable(statementSql);
          if (statementUsesRelevantDatabase(statementTable, currentDatabase)) {
            const auto change = analyzeStatement(mysql, recordDomains, statementSql);
            if (change.needsFullResync) {
              logInfo("statement event requires full resync sql='" + oneLine(statementSql) + "'");
              forceFullResync = true;
              break;
            }
            changedZones.insert(change.changedZones.begin(), change.changedZones.end());
            deletedZones.insert(change.deletedZones.begin(), change.deletedZones.end());
            syncTSIG = syncTSIG || change.syncTSIG;
            if (!changedZones.empty() || !deletedZones.empty() || syncTSIG) {
              applyChangedZones(mysql, lmdb, recordDomains, changedZones, deletedZones, syncTSIG);
              changedZones.clear();
              deletedZones.clear();
              syncTSIG = false;
              saveAppliedState(lmdb, pos);
              appliedPos = pos;
            }
          }
          statementSql.clear();
        }
        continue;
      }

      if (line.find("### INSERT INTO `") == 0 ||
          line.find("### UPDATE `") == 0 ||
          line.find("### DELETE FROM `") == 0) {
        if (table == "domains") {
          if (deleteDomainRow) {
            if (oldDomainRowName) {
              deletedZones.insert(*oldDomainRowName);
            }
            else {
              forceFullResync = true;
              break;
            }
          }
          else if (oldDomainRowName || newDomainRowName) {
            if (!oldDomainRowName || !newDomainRowName || *oldDomainRowName == *newDomainRowName) {
              changedZones.insert(newDomainRowName ? *newDomainRowName : *oldDomainRowName);
            }
            else {
              deletedZones.insert(*oldDomainRowName);
              changedZones.insert(*newDomainRowName);
            }
          }
        }
        table.clear();
        domainRowId = UnknownDomainID;
        domainRowIdSet = false;
        oldDomainRowName.reset();
        newDomainRowName.reset();
        deleteDomainRow = line.find("### DELETE FROM") == 0;
        domainValuesAreNew = line.find("### INSERT INTO") == 0;
        const auto rowTable = parseRowEventDatabaseTable(line);
        if (rowTable && toLowerASCII(rowTable->first) == toLowerASCII(getArg("mysql-dbname"))) {
          table = toLowerASCII(rowTable->second);
          if (table == "tsigkeys") {
            syncTSIG = true;
          }
        }
        continue;
      }

      if (table == "domains" && line == "### SET") {
        domainValuesAreNew = true;
        continue;
      }

      if (line.rfind("###   @", 0) == 0) {
        if (table == "records" || table == "comments" || table == "domainmetadata" || table == "cryptokeys") {
          if (line.rfind("###   @2=", 0) == 0) {
            const auto id = parseRowIntValue(line);
            if (id) {
              const auto rowDomainId = static_cast<domainid_t>(*id);
              if (const auto zone = getZoneById(mysql, rowDomainId)) {
                changedZones.insert(*zone);
              }
            }
          }
        }
        else if (table == "domains") {
          if (line.rfind("###   @1=", 0) == 0) {
            const auto id = parseRowIntValue(line);
            if (id) {
              domainRowId = static_cast<domainid_t>(*id);
              domainRowIdSet = true;
            }
          }
          else if (line.rfind("###   @2=", 0) == 0) {
            const auto name = parseRowStringValue(line);
            if (name && !name->empty() && *name != "NULL") {
              try {
                if (deleteDomainRow || !domainValuesAreNew) {
                  oldDomainRowName = ZoneName(*name);
                }
                else {
                  newDomainRowName = ZoneName(*name);
                }
              }
              catch (const std::exception& e) {
                const auto message = "Invalid MySQL domain row from binlog name='" + *name + "': " + e.what();
                if (handleInvalidSourceData(message)) {
                  continue;
                }
              }
            }
          }
        }
        continue;
      }

      if (line.find("Xid = ") != std::string::npos || rowCommitLine) {
        const bool hadDomainRowName = oldDomainRowName.has_value() || newDomainRowName.has_value();
        if (table == "domains") {
          if (deleteDomainRow) {
            if (oldDomainRowName) {
              deletedZones.insert(*oldDomainRowName);
            }
            else {
              forceFullResync = true;
              break;
            }
          }
          else if (oldDomainRowName || newDomainRowName) {
            if (!oldDomainRowName || !newDomainRowName || *oldDomainRowName == *newDomainRowName) {
              changedZones.insert(newDomainRowName ? *newDomainRowName : *oldDomainRowName);
            }
            else {
              deletedZones.insert(*oldDomainRowName);
              changedZones.insert(*newDomainRowName);
            }
          }
          oldDomainRowName.reset();
          newDomainRowName.reset();
        }
        if (domainRowIdSet && !hadDomainRowName && !deleteDomainRow) {
          if (const auto zone = getZoneById(mysql, domainRowId)) {
            changedZones.insert(*zone);
          }
        }
        table.clear();
        domainRowId = UnknownDomainID;
        domainRowIdSet = false;
        deleteDomainRow = false;
        domainValuesAreNew = false;
        if (!changedZones.empty() || !deletedZones.empty() || syncTSIG) {
          applyChangedZones(mysql, lmdb, recordDomains, changedZones, deletedZones, syncTSIG);
          changedZones.clear();
          deletedZones.clear();
          syncTSIG = false;
          if (haveCurrentEventEndPos && currentEventEndPos != 0) {
            pos.pos = currentEventEndPos;
          }
          saveAppliedState(lmdb, pos);
          appliedPos = pos;
        }
      }
    }

    const auto status = child.close(forceFullResync || missingBinlog);
    if (forceFullResync || missingBinlog) {
      std::string reason = "binlog stream stopped";
      if (forceFullResync) {
        reason = "binlog event could not be mapped safely to zones";
      }
      else if (missingBinlog) {
        reason = "saved binlog is missing or unreadable";
      }
      logWarning("incremental stream stopped; running full resync reason='" + reason + "'");
      if (status != 0) {
        logRecentMysqlbinlogOutput(recentMysqlbinlogOutput);
      }
      pos = fullResync(mysql, lmdb, recordDomains, reason);
      saveAppliedState(lmdb, pos);
      appliedPos = pos;
    }
    else if (status != 0) {
      logWarning("mysqlbinlog exited with " + describeProcessStatus(status) + "; reconnecting from last applied position=" + describePosition(appliedPos));
      logRecentMysqlbinlogOutput(recentMysqlbinlogOutput);
      pos = appliedPos;
    }
    else if (const auto nextLog = mysql.nextBinaryLog(pos.file)) {
      pos.file = *nextLog;
      pos.pos = 4;
      logInfo("continuing with next binlog position=" + describePosition(pos));
      continue;
    }

    if (getBoolArg("once")) {
      logInfo("once mode completed");
      return;
    }
    logInfo("incremental stream ended cleanly; retrying after " + std::to_string(::arg().asNum("retry-interval", 5)) + " seconds");
    std::this_thread::sleep_for(std::chrono::seconds(::arg().asNum("retry-interval", 5)));
  }
}

void declareArguments()
{
  ::arg().set("mysql-host", "MySQL primary host") = "127.0.0.1";
  ::arg().set("mysql-port", "MySQL primary port") = "3306";
  ::arg().set("mysql-socket", "MySQL unix socket") = "";
  ::arg().set("mysql-user", "MySQL replication user") = "powerdns";
  ::arg().set("mysql-password", "MySQL replication user password") = "";
  ::arg().set("mysql-defaults-file", "MySQL defaults file containing client credentials") = "";
  ::arg().set("mysql-dbname", "MySQL PowerDNS database name") = "powerdns";
  ::arg().set("mysql-timeout", "MySQL client timeout in seconds") = "10";
  ::arg().set("mysqlbinlog", "Path to mysqlbinlog client") = "mysqlbinlog";
  ::arg().set("state-file", "Replication state file") = "./pdns-mysql2lmdb.state";
  ::arg().set("retry-interval", "Seconds to wait before retrying a stopped binlog stream") = "5";
  ::arg().set("soa-serial-overflow", "How to handle SOA serials larger than 32 bits: reject, modulo, clamp") = "reject";
  ::arg().set("invalid-records", "How to handle invalid MySQL records: reject, skip") = "reject";

  ::arg().setSwitch("allow-missing-mysqlbinlog", "Allow startup without mysqlbinlog; incremental replication will not work") = "no";
  ::arg().setSwitch("full", "Run a full resync before following the binlog") = "no";
  ::arg().setSwitch("once", "Exit after the initial full resync or one binlog stream attempt") = "no";
  ::arg().setCmd("help", "Provide a helpful message");
  ::arg().setCmd("version", "Print the version");

  ::arg().setSwitch("views", "Enable view support for the LMDB backend") = "no";
  ::arg().setSwitch("query-logging", "Enable LMDB query logging") = "no";
  ::arg().set("lmdb-filename", "Filename for lmdb") = "./pdns.lmdb";
  ::arg().set("lmdb-sync-mode", "LMDB sync mode") = "nosync";
  ::arg().set("lmdb-map-size", "main LMDB map size in megabytes") = (sizeof(void*) == 4) ? "100" : "16000";
  ::arg().set("lmdb-shards-map-size", "shard LMDB map size in megabytes, zero to use the same size as main") = "0";
  ::arg().set("lmdb-shards", "Number of LMDB record shards") = (sizeof(void*) == 4) ? "2" : "64";
  ::arg().set("lmdb-schema-version", "LMDB schema version") = std::to_string(LMDBBackend::CurrentSchemaVersion);
  ::arg().setSwitch("lmdb-random-ids", "Use random LMDB object ids") = "no";
  ::arg().setSwitch("lmdb-lightning-stream", "Run in Lightning Stream compatible mode") = "no";
  ::arg().setSwitch("lmdb-flag-deleted", "Keep deleted records flagged in LMDB") = "no";
  ::arg().setSwitch("lmdb-write-notification-update", "Persist notification updates in LMDB") = "yes";
  ::arg().setSwitch("lmdb-split-domains-table", "Store volatile domain data in a separate LMDB table") = "no";
}

} // namespace

int main(int argc, char** argv)
try
{
  reportAllTypes();
  declareArguments();
  ::arg().setDefaults();
  ::arg().parse(argc, argv);

  if (::arg().mustDo("version")) {
    std::cout << "pdns-mysql2lmdb " << VERSION << std::endl;
    return 0;
  }

  if (::arg().mustDo("help")) {
    std::cout << "syntax:\n\n" << ::arg().helpstring() << std::endl;
    return 0;
  }

  if (!getArg("mysql-password").empty() && getArg("mysql-defaults-file").empty() && !::arg().mustDo("allow-missing-mysqlbinlog")) {
    throw std::runtime_error("--mysql-password is not passed to mysqlbinlog because it is visible in process listings; use --mysql-defaults-file for production credentials");
  }

  if (!executableExists(getArg("mysqlbinlog"))) {
    const auto message = "mysqlbinlog executable '" + getArg("mysqlbinlog") + "' was not found or is not executable; install mysqlbinlog or set --mysqlbinlog=/path/to/mysqlbinlog";
    if (::arg().mustDo("allow-missing-mysqlbinlog")) {
      logWarning(message + "; continuing because --allow-missing-mysqlbinlog is set");
    }
    else {
      throw std::runtime_error(message);
    }
  }

  MySQL mysql;
  validateBinlogSettings(mysql);
  LMDBBackend lmdb;
  RecordDomainMap recordDomains;

  logInfo("startup mysql_db='" + getArg("mysql-dbname") + "' lmdb='" + getArg("lmdb-filename") + "' state_file='" + resolvedStateFile() + "' defaults_file=" + std::string(getArg("mysql-defaults-file").empty() ? "no" : "yes") + " once=" + std::string(getBoolArg("once") ? "yes" : "no") + " force_full=" + std::string(::arg().mustDo("full") ? "yes" : "no"));
  auto state = loadState();
  if (::arg().mustDo("full") || !state) {
    const auto reason = ::arg().mustDo("full") ? std::string("--full requested") : std::string("no saved replication state");
    if (!state) {
      logInfo("no saved replication state found file='" + resolvedStateFile() + "'");
    }
    state = fullResync(mysql, lmdb, recordDomains, reason);
    saveAppliedState(lmdb, *state);
    if (::arg().mustDo("once")) {
      logInfo("once mode completed after full resync");
      return 0;
    }
  }
  else {
    logInfo("saved replication state found; skipping initial full resync");
    loadRecordDomainMap(mysql, recordDomains);
  }

  followBinlog(mysql, lmdb, recordDomains, *state);
  return 0;
}
catch (const std::exception& e) {
  std::cerr << "Fatal: " << e.what() << std::endl;
  return 1;
}
catch (const PDNSException& e) {
  std::cerr << "Fatal: " << e.reason << std::endl;
  return 1;
}
