//! File quarantine used by the `files.quarantine` and `files.restore` blocks.
//!
//! [`quarantine`] moves the regular files directly inside an allowlisted root
//! whose names match a glob (`*`, `?`) into a destination directory and
//! records them in `manifest.json` (`original` path, `stored` name, `size`,
//! `sha256`). The manifest is written before any file moves, so a crash
//! midway leaves a manifest that [`restore`] can still act on. Symlinks and
//! other non-regular entries are never followed or moved.
//!
//! This crate has no hashing or JSON dependency; both are implemented here
//! for exactly what the manifest needs.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::PlatformError;

/// Result alias of this module.
pub type Result<T> = std::result::Result<T, PlatformError>;

/// Manifest file name inside the destination directory.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Longest accepted glob pattern.
const MAX_PATTERN: usize = 255;

/// One file moved into quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedFile {
    /// Where the file was.
    pub original: PathBuf,
    /// Where it is now.
    pub stored: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the content.
    pub sha256: [u8; 32],
}

/// The platform's allowlisted quarantine roots. Windows:
/// `%SystemRoot%\System32\spool\PRINTERS`; none elsewhere this phase.
pub fn allowed_roots() -> Vec<PathBuf> {
    spool_root().into_iter().collect()
}

/// The print spool directory, where the platform has one.
pub fn spool_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Some(
            PathBuf::from(base)
                .join("System32")
                .join("spool")
                .join("PRINTERS"),
        )
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn io_err(what: &str, path: &Path, e: &io::Error) -> PlatformError {
    PlatformError::Os(format!("{what} {}: {e}", path.display()))
}

fn refuse(m: String) -> PlatformError {
    PlatformError::Refused(m)
}

/// [`quarantine_in`] against [`allowed_roots`].
pub fn quarantine(root: &Path, pattern: &str, dest_dir: &Path) -> Result<Vec<QuarantinedFile>> {
    quarantine_in(&allowed_roots(), root, pattern, dest_dir)
}

/// Move the regular files directly in `root` whose names match `pattern`
/// into `dest_dir`. `root` must be a real directory (not a symlink) equal to
/// one of `allowed`; otherwise nothing is touched. Calling it again with the
/// same `dest_dir` adds to the existing manifest.
pub fn quarantine_in(
    allowed: &[PathBuf],
    root: &Path,
    pattern: &str,
    dest_dir: &Path,
) -> Result<Vec<QuarantinedFile>> {
    check_pattern(pattern)?;
    check_root(allowed, root)?;
    fs::create_dir_all(dest_dir).map_err(|e| io_err("create", dest_dir, &e))?;

    let mut entries = read_manifest(dest_dir)?.unwrap_or_default();
    let mut next = entries
        .iter()
        .filter_map(|e| e.stored.parse::<u64>().ok())
        .max()
        .map_or(0, |n| n + 1);
    let mut planned = Vec::new();
    let dir = fs::read_dir(root).map_err(|e| io_err("list", root, &e))?;
    for entry in dir {
        let entry = entry.map_err(|e| io_err("list", root, &e))?;
        // DirEntry::file_type does not follow symlinks.
        let ft = entry
            .file_type()
            .map_err(|e| io_err("stat", &entry.path(), &e))?;
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !glob_match(pattern, name) {
            continue;
        }
        let original = entry.path();
        let Some(original_str) = original.to_str() else {
            continue;
        };
        let (size, sha256) = hash_file(&original)?;
        let stored = format!("{next:06}");
        next += 1;
        planned.push(Entry {
            original: original_str.to_owned(),
            stored,
            size,
            sha256,
        });
    }
    if planned.is_empty() {
        return Ok(Vec::new());
    }
    entries.extend(planned.iter().cloned());
    write_manifest(dest_dir, &entries)?;

    let mut moved = Vec::with_capacity(planned.len());
    for e in planned {
        let original = PathBuf::from(&e.original);
        let stored = dest_dir.join(&e.stored);
        move_file(&original, &stored)?;
        moved.push(QuarantinedFile {
            original,
            stored,
            size: e.size,
            sha256: e.sha256,
        });
    }
    Ok(moved)
}

/// Move every quarantined file in `dest_dir` back. Returns how many moved.
/// A missing manifest restores nothing. Refuses (and moves nothing) if an
/// original path exists again or a stored file's hash changed. On success
/// the manifest and `dest_dir` are removed.
pub fn restore(dest_dir: &Path) -> Result<usize> {
    let Some(entries) = read_manifest(dest_dir)? else {
        return Ok(0);
    };
    let mut todo = Vec::new();
    for e in &entries {
        if e.stored.contains(['/', '\\']) || e.stored.contains("..") {
            return Err(refuse(format!("bad stored name {:?}", e.stored)));
        }
        let stored = dest_dir.join(&e.stored);
        let original = PathBuf::from(&e.original);
        match fs::symlink_metadata(&stored) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err(refuse(format!("{} is not a file", stored.display()))),
            // Never moved (the quarantine stopped midway).
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err("stat", &stored, &e)),
        }
        if fs::symlink_metadata(&original).is_ok() {
            return Err(refuse(format!(
                "{} exists; refusing to overwrite it",
                original.display()
            )));
        }
        let (size, sha) = hash_file(&stored)?;
        if size != e.size || sha != e.sha256 {
            return Err(refuse(format!(
                "{} changed in quarantine",
                stored.display()
            )));
        }
        todo.push((stored, original));
    }
    for (stored, original) in &todo {
        move_file(stored, original)?;
    }
    let manifest = dest_dir.join(MANIFEST_FILE);
    fs::remove_file(&manifest).map_err(|e| io_err("remove", &manifest, &e))?;
    let _ = fs::remove_dir(dest_dir);
    Ok(todo.len())
}

fn check_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty()
        || pattern.len() > MAX_PATTERN
        || pattern.contains(['/', '\\', '\0'])
        || pattern.contains("..")
    {
        return Err(refuse(format!("invalid file pattern {pattern:?}")));
    }
    Ok(())
}

fn check_root(allowed: &[PathBuf], root: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(root).map_err(|e| io_err("stat", root, &e))?;
    if !meta.is_dir() {
        return Err(refuse(format!(
            "{} is not a directory (or is a symlink)",
            root.display()
        )));
    }
    let canon = fs::canonicalize(root).map_err(|e| io_err("resolve", root, &e))?;
    if allowed
        .iter()
        .filter_map(|a| fs::canonicalize(a).ok())
        .any(|a| a == canon)
    {
        Ok(())
    } else {
        Err(refuse(format!(
            "{} is not an allowlisted root",
            root.display()
        )))
    }
}

/// Rename, falling back to copy and remove (other volume).
fn move_file(from: &Path, to: &Path) -> Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    if fs::symlink_metadata(to).is_ok() {
        return Err(refuse(format!("{} exists", to.display())));
    }
    fs::copy(from, to).map_err(|e| io_err("copy", from, &e))?;
    fs::remove_file(from).map_err(|e| {
        let _ = fs::remove_file(to);
        io_err("remove", from, &e)
    })
}

/// Glob match on a file name: `*` is any run, `?` any one character.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut f = File::open(path).map_err(|e| io_err("open", path, &e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| io_err("read", path, &e))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        h.update(&buf[..n]);
    }
    Ok((size, h.finish()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    original: String,
    stored: String,
    size: u64,
    sha256: [u8; 32],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn encode_manifest(entries: &[Entry]) -> String {
    let mut out = String::from("{\"v\":1,\"files\":[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"original\":");
        json_str(&mut out, &e.original);
        out.push_str(",\"stored\":");
        json_str(&mut out, &e.stored);
        out.push_str(&format!(
            ",\"size\":{},\"sha256\":\"{}\"}}",
            e.size,
            hex(&e.sha256)
        ));
    }
    out.push_str("]}\n");
    out
}

fn write_manifest(dest_dir: &Path, entries: &[Entry]) -> Result<()> {
    let path = dest_dir.join(MANIFEST_FILE);
    let tmp = dest_dir.join(format!("{MANIFEST_FILE}.tmp"));
    let write = || -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(encode_manifest(entries).as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err("write", &path, &e)
    })
}

fn read_manifest(dest_dir: &Path) -> Result<Option<Vec<Entry>>> {
    let path = dest_dir.join(MANIFEST_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("read", &path, &e)),
    };
    decode_manifest(&text)
        .map(Some)
        .ok_or_else(|| refuse(format!("{} is malformed", path.display())))
}

fn decode_manifest(text: &str) -> Option<Vec<Entry>> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
        depth: 0,
    };
    let v = p.value()?;
    p.ws();
    if p.i != p.s.len() {
        return None;
    }
    let Json::Obj(top) = v else { return None };
    if get(&top, "v")? != &Json::Num(1) {
        return None;
    }
    let Json::Arr(files) = get(&top, "files")? else {
        return None;
    };
    files
        .iter()
        .map(|f| {
            let Json::Obj(f) = f else { return None };
            let s = |k: &str| match get(f, k)? {
                Json::Str(s) => Some(s.clone()),
                _ => None,
            };
            let Json::Num(size) = get(f, "size")? else {
                return None;
            };
            Some(Entry {
                original: s("original")?,
                stored: s("stored")?,
                size: *size,
                sha256: unhex32(&s("sha256")?)?,
            })
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

fn get<'a>(obj: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Minimal JSON reader: unsigned integers only, nesting depth at most 8.
struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: u8,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(u8::is_ascii_whitespace) {
            self.i += 1;
        }
    }

    fn eat(&mut self, b: u8) -> Option<()> {
        self.ws();
        (self.s.get(self.i) == Some(&b)).then(|| self.i += 1)
    }

    fn lit(&mut self, word: &[u8], v: Json) -> Option<Json> {
        self.s[self.i..].starts_with(word).then(|| {
            self.i += word.len();
            v
        })
    }

    fn value(&mut self) -> Option<Json> {
        self.ws();
        match *self.s.get(self.i)? {
            b'{' | b'[' => {
                self.depth += 1;
                if self.depth > 8 {
                    return None;
                }
                let v = if self.s[self.i] == b'{' {
                    self.object()
                } else {
                    self.array()
                };
                self.depth -= 1;
                v
            }
            b'"' => self.string().map(Json::Str),
            b't' => self.lit(b"true", Json::Bool(true)),
            b'f' => self.lit(b"false", Json::Bool(false)),
            b'n' => self.lit(b"null", Json::Null),
            b'0'..=b'9' => {
                let start = self.i;
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
                std::str::from_utf8(&self.s[start..self.i])
                    .ok()?
                    .parse()
                    .ok()
                    .map(Json::Num)
            }
            _ => None,
        }
    }

    fn object(&mut self) -> Option<Json> {
        self.eat(b'{')?;
        let mut out = Vec::new();
        if self.eat(b'}').is_some() {
            return Some(Json::Obj(out));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.eat(b':')?;
            out.push((k, self.value()?));
            if self.eat(b',').is_none() {
                self.eat(b'}')?;
                return Some(Json::Obj(out));
            }
        }
    }

    fn array(&mut self) -> Option<Json> {
        self.eat(b'[')?;
        let mut out = Vec::new();
        if self.eat(b']').is_some() {
            return Some(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            if self.eat(b',').is_none() {
                self.eat(b']')?;
                return Some(Json::Arr(out));
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = std::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
        self.i += 4;
        u32::from_str_radix(h, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        if self.s.get(self.i) != Some(&b'"') {
            return None;
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let b = *self.s.get(self.i)?;
            self.i += 1;
            match b {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i..self.i + 2)? != b"\\u" {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    };
                    let mut tmp = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                }
                0..=0x1f => return None,
                b => out.push(b),
            }
        }
    }
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming SHA-256 (FIPS 180-4).
struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    used: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            used: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let n = (64 - self.used).min(data.len());
            self.buf[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used == 64 {
                let block = self.buf;
                self.compress(&block);
                self.used = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.used != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (o, h) in out.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&h.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        hex(&h.finish())
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmm-q-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn glob() {
        assert!(glob_match("*", "a.spl"));
        assert!(glob_match("*.spl", "00012.spl"));
        assert!(!glob_match("*.spl", "00012.shd"));
        assert!(glob_match("fp?.tmp", "fp1.tmp"));
        assert!(!glob_match("fp?.tmp", "fp12.tmp"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }

    #[test]
    fn manifest_round_trip_with_escapes() {
        let entries = vec![Entry {
            original: "C:\\spool\\\"odd\"\nname\u{1}é😀".into(),
            stored: "000000".into(),
            size: 42,
            sha256: [7; 32],
        }];
        let text = encode_manifest(&entries);
        assert_eq!(decode_manifest(&text), Some(entries));
        assert_eq!(decode_manifest("{\"v\":2,\"files\":[]}"), None);
        assert_eq!(decode_manifest("{\"v\":1,\"files\":[]} x"), None);
        assert_eq!(decode_manifest("{\"v\":1,\"files\":[]}"), Some(Vec::new()));
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let base = scratch("rt");
        let root = base.join("spool");
        let dest = base.join("q").join("cmd1");
        fs::create_dir_all(root.join("sub")).expect("root");
        fs::write(root.join("a.spl"), b"job a").expect("a");
        fs::write(root.join("a.shd"), b"shadow a").expect("a shd");
        fs::write(root.join("keep.txt"), b"keep").expect("keep");
        fs::write(root.join("sub").join("deep.spl"), b"deep").expect("deep");

        let moved =
            quarantine_in(std::slice::from_ref(&root), &root, "a.*", &dest).expect("quarantine");
        assert_eq!(moved.len(), 2);
        assert!(!root.join("a.spl").exists());
        assert!(!root.join("a.shd").exists());
        assert!(root.join("keep.txt").exists());
        assert!(root.join("sub").join("deep.spl").exists(), "not recursive");
        let a = moved
            .iter()
            .find(|m| m.original.ends_with("a.spl"))
            .expect("a moved");
        assert_eq!(a.size, 5);
        let mut h = Sha256::new();
        h.update(b"job a");
        assert_eq!(a.sha256, h.finish());
        assert!(dest.join(MANIFEST_FILE).exists());

        // Nothing left to match: no-op.
        assert!(
            quarantine_in(std::slice::from_ref(&root), &root, "a.*", &dest)
                .expect("again")
                .is_empty()
        );

        assert_eq!(restore(&dest).expect("restore"), 2);
        assert_eq!(fs::read(root.join("a.spl")).expect("a back"), b"job a");
        assert_eq!(fs::read(root.join("a.shd")).expect("shd back"), b"shadow a");
        assert!(!dest.exists(), "quarantine dir removed");
        assert_eq!(restore(&dest).expect("nothing to restore"), 0);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn restore_refuses_to_overwrite() {
        let base = scratch("ow");
        let root = base.join("spool");
        let dest = base.join("q");
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join("x"), b"old").expect("x");
        quarantine_in(std::slice::from_ref(&root), &root, "*", &dest).expect("quarantine");
        fs::write(root.join("x"), b"new").expect("new x");
        assert!(matches!(restore(&dest), Err(PlatformError::Refused(_))));
        assert_eq!(fs::read(root.join("x")).expect("x"), b"new", "untouched");
        fs::remove_file(root.join("x")).expect("rm");
        assert_eq!(restore(&dest).expect("restore"), 1);
        assert_eq!(fs::read(root.join("x")).expect("x"), b"old");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn root_outside_allowlist_is_refused_untouched() {
        let base = scratch("allow");
        let root = base.join("spool");
        let other = base.join("other");
        let dest = base.join("q");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&other).expect("other");
        fs::write(other.join("f"), b"f").expect("f");
        let err = quarantine_in(std::slice::from_ref(&root), &other, "*", &dest);
        assert!(matches!(err, Err(PlatformError::Refused(_))), "{err:?}");
        assert!(other.join("f").exists());
        assert!(!dest.exists(), "nothing created");
        // The real allowlist is empty off Windows.
        if cfg!(not(windows)) {
            assert!(allowed_roots().is_empty());
            assert!(quarantine(&root, "*", &dest).is_err());
        }
        assert!(quarantine_in(std::slice::from_ref(&root), &root, "../*", &dest).is_err());
        assert!(quarantine_in(std::slice::from_ref(&root), &root, "a/b", &dest).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_and_never_roots() {
        use std::os::unix::fs::symlink;
        let base = scratch("link");
        let root = base.join("spool");
        let outside = base.join("outside");
        let dest = base.join("q");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("secret"), b"s").expect("secret");
        fs::write(root.join("job"), b"j").expect("job");
        symlink(outside.join("secret"), root.join("link")).expect("file link");
        symlink(&outside, root.join("dirlink")).expect("dir link");

        let moved =
            quarantine_in(std::slice::from_ref(&root), &root, "*", &dest).expect("quarantine");
        assert_eq!(moved.len(), 1);
        assert!(moved[0].original.ends_with("job"));
        assert!(
            fs::symlink_metadata(root.join("link"))
                .expect("link stays")
                .file_type()
                .is_symlink()
        );
        assert!(outside.join("secret").exists());

        // A symlinked root is refused even if it points at an allowed root.
        let alias = base.join("alias");
        symlink(&root, &alias).expect("root link");
        assert!(matches!(
            quarantine_in(std::slice::from_ref(&root), &alias, "*", &dest),
            Err(PlatformError::Refused(_))
        ));
        let _ = fs::remove_dir_all(&base);
    }
}
