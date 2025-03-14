use crypto::sha1;
use crypto::sha256;

export type oid = (oid_sha1 | oid_sha256);
export type oid_sha1 = [sha1::SZ]u8;
export type oid_sha256 = [sha256::SZ]u8;
