use crypto::sha1;
use crypto::sha256;
use encoding::hex;
use errors;
use io;

export type oid = (oid_sha1 | oid_sha256);
export type oid_sha1 = [sha1::SZ]u8;
export type oid_sha256 = [sha256::SZ]u8;

// oid_from_str converts a hex string to an oid.
export fn oid_from_str(s: const str) (oid | nomem | errors::invalid) = {
	const d = match (hex::decodestr(s)) {
	case let u: []u8 => yield u;
	case nomem => return nomem;
	case errors::invalid => return errors::invalid;
	case => abort("unreachable");
	};
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
		return errors::invalid;
	};

	return o;
};
