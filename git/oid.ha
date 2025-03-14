use crypto::sha1;
use crypto::sha256;
use encoding::hex;
use io;

// Invalid hash length
export type hashlen = !void;

export type oid = (oid_sha1 | oid_sha256);
export type oid_sha1 = [sha1::SZ]u8;
export type oid_sha256 = [sha256::SZ]u8;

export fn oid_from_str(s: const str) (oid | io::error | hashlen) = {
	const d = hex::decodestr(s)?;
	defer free(d);

	let o: oid = switch (len(s)) {
	case sha1::SZ =>
		let p: oid_sha1 = [0...];
		p[..] = d[..];
		yield p;
	case sha256::SZ => 
		let p: oid_sha256 = [0...];
		p[..] = d[..];
		yield p;
	case =>
		return hashlen;
	};

	return o;
};
