// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Seed only a fresh test profile, before Chrome starts. No OS trust changes.
const { mkdirSync, readFileSync, chmodSync } = require("node:fs");
const { join } = require("node:path");
const { X509Certificate, createHash } = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

function trustCertificate(profile, certificate) {
  const der = new X509Certificate(readFileSync(certificate)).raw;
  const directory = join(profile, "Default");
  // Deliberately refuse an existing profile, including a symlink.
  mkdirSync(directory, { mode: 0o700 });
  const path = join(directory, "ServerCertificate");
  const database = new DatabaseSync(path);
  try {
    chmodSync(path, 0o600);
    // Chromium schema v1 and CertificateMetadata.trust.trust_type = TRUSTED.
    // components/server_certificate_database/server_certificate_database.{cc,proto}
    // Verified against Chromium 153.0.8010.47. Browser tests fail if incompatible.
    database.exec("BEGIN; CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);" +
      "INSERT INTO meta VALUES('version','1'),('last_compatible_version','1');" +
      "CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL);");
    database.prepare("INSERT INTO certificates VALUES(?,?,?)").run(
      createHash("sha256").update(der).digest("hex"), der, Buffer.from("0a020803", "hex"));
    database.exec("COMMIT");
  } finally {
    database.close();
  }
}

if (require.main === module) {
  try {
    if (process.argv.length !== 4) throw new Error("arguments");
    trustCertificate(process.argv[2], process.argv[3]);
  } catch (_) {
    process.stderr.write("unable to prepare private browser certificate trust\n");
    process.exitCode = 1;
  }
}
module.exports = { trustCertificate };
