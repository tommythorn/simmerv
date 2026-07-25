//! URL-backed block storage with a copy-on-write overlay.
//!
//! Reads of unmodified sectors are fetched from an HTTP(S) URL using `Range`
//! requests (in large blocks, cached in memory), so a boot only pulls the
//! sectors it actually touches. Writes never go back to the server — they land
//! in an in-memory overlay, and later reads of those sectors are served from
//! the overlay. This lets you point `-f` straight at a raw disk image on a web
//! server and boot off it read-only-at-the-source.
//!
//! Only *uncompressed* images work: HTTP ranges address the compressed bytes,
//! but reading decompressed sector N would require decompressing the whole
//! stream, so compressed URLs are rejected up front.

use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;
use std::time::Duration;

const SECTOR_SIZE: usize = 512;

/// Granularity of base-image fetches. Reads miss at most one block per gap, so
/// a larger block trades memory and per-miss latency for fewer round-trips.
const BLOCK_SIZE: u64 = 1 << 20; // 1 MiB

/// Retries for a failed range fetch before giving up (the run loop is blocked
/// during a fetch, so guest time does not advance meanwhile).
const FETCH_RETRIES: u32 = 3;

/// A block device whose base image lives at a URL, with local copy-on-write.
pub struct UrlStorage {
    url: String,
    /// Total size of the base image in bytes.
    len: u64,
    agent: ureq::Agent,
    /// Base-image blocks fetched from the server, keyed by block index.
    /// `RefCell` because reads (`&self`) populate it lazily.
    read_cache: RefCell<HashMap<u64, Rc<Vec<u8>>>>,
    /// Written sectors (copy-on-write), keyed by sector index.
    overlay: BTreeMap<u64, [u8; SECTOR_SIZE]>,
}

impl UrlStorage {
    /// Opens a URL-backed disk: validates the scheme, rejects compressed
    /// images, and probes the server for the image size and range support.
    ///
    /// # Errors
    /// Returns an error if the URL is not http(s), points at a compressed
    /// image, the server does not support range requests, or the probe fails.
    pub fn open(url: &str) -> anyhow::Result<Self> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("not an http(s) URL: {url}");
        }
        reject_if_compressed(url)?;

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .build();

        let len = probe_len(&agent, url)
            .with_context(|| format!("probing {url} for size / range support"))?;
        if len == 0 {
            bail!("{url}: server reported a zero-length image");
        }

        Ok(Self {
            url: url.to_string(),
            len,
            agent,
            read_cache: RefCell::new(HashMap::new()),
            overlay: BTreeMap::new(),
        })
    }

    /// Number of whole 512-byte sectors in the base image.
    #[must_use]
    pub const fn sector_count(&self) -> u64 { self.len / SECTOR_SIZE as u64 }

    /// Reads `buf.len()` bytes starting at byte `offset` (sector-aligned in
    /// practice), preferring the copy-on-write overlay over the base image.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) {
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            let sector = cur / SECTOR_SIZE as u64;
            let within = (cur % SECTOR_SIZE as u64) as usize;
            let n = (SECTOR_SIZE - within).min(buf.len() - done);
            if let Some(sec) = self.overlay.get(&sector) {
                buf[done..done + n].copy_from_slice(&sec[within..within + n]);
            } else {
                self.base_read(cur, &mut buf[done..done + n]);
            }
            done += n;
        }
    }

    /// Writes `data` starting at byte `offset` into the overlay only; the base
    /// image at the URL is never modified. Sub-sector writes preserve the
    /// surrounding bytes by reading the base sector first.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) {
        let mut done = 0usize;
        while done < data.len() {
            let cur = offset + done as u64;
            let sector = cur / SECTOR_SIZE as u64;
            let within = (cur % SECTOR_SIZE as u64) as usize;
            let n = (SECTOR_SIZE - within).min(data.len() - done);
            if !self.overlay.contains_key(&sector) {
                let mut sec = [0u8; SECTOR_SIZE];
                // Only fetch the base sector for a partial write; a full-sector
                // overwrite discards it anyway.
                if within != 0 || n != SECTOR_SIZE {
                    self.base_read(sector * SECTOR_SIZE as u64, &mut sec);
                }
                self.overlay.insert(sector, sec);
            }
            if let Some(sec) = self.overlay.get_mut(&sector) {
                sec[within..within + n].copy_from_slice(&data[done..done + n]);
            }
            done += n;
        }
    }

    /// Fills `out` with base-image bytes `[offset, offset + out.len())`,
    /// fetching and caching whole blocks from the server as needed.
    fn base_read(&self, offset: u64, out: &mut [u8]) {
        let mut done = 0usize;
        while done < out.len() {
            let cur = offset + done as u64;
            let block_idx = cur / BLOCK_SIZE;
            let block = self.ensure_block(block_idx);
            let within = (cur - block_idx * BLOCK_SIZE) as usize;
            let n = (block.len() - within).min(out.len() - done);
            out[done..done + n].copy_from_slice(&block[within..within + n]);
            done += n;
        }
    }

    /// Returns block `block_idx` of the base image, fetching and caching it on
    /// first access.
    fn ensure_block(&self, block_idx: u64) -> Rc<Vec<u8>> {
        if let Some(block) = self.read_cache.borrow().get(&block_idx) {
            return Rc::clone(block);
        }
        let start = block_idx * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(self.len) - 1; // inclusive
        let bytes = self.fetch_range(start, end);
        let block = Rc::new(bytes);
        self.read_cache
            .borrow_mut()
            .insert(block_idx, Rc::clone(&block));
        block
    }

    /// Fetches bytes `[start, end]` (inclusive) via a `Range` request, retrying
    /// transient failures. Panics after exhausting retries — a disk read that
    /// cannot be satisfied is unrecoverable, matching the file-backed backend.
    #[allow(clippy::expect_used)]
    fn fetch_range(&self, start: u64, end: u64) -> Vec<u8> {
        let expected = (end - start + 1) as usize;
        let mut last_err = String::new();
        for attempt in 0..FETCH_RETRIES {
            match self.try_fetch_range(start, end) {
                Ok(bytes) if bytes.len() == expected => return bytes,
                Ok(bytes) => {
                    last_err = format!("short read: got {} bytes, want {expected}", bytes.len());
                }
                Err(e) => last_err = e.to_string(),
            }
            log::warn!(
                "disk fetch {}-{end} from {} failed (attempt {}/{FETCH_RETRIES}): {last_err}",
                start,
                self.url,
                attempt + 1
            );
            std::thread::sleep(Duration::from_millis(200 * u64::from(attempt + 1)));
        }
        panic!(
            "disk read {start}-{end} from {} failed: {last_err}",
            self.url
        );
    }

    fn try_fetch_range(&self, start: u64, end: u64) -> anyhow::Result<Vec<u8>> {
        let resp = self
            .agent
            .get(&self.url)
            .set("Range", &format!("bytes={start}-{end}"))
            .call()?;
        if resp.status() != 206 {
            bail!("expected 206 Partial Content, got {}", resp.status());
        }
        let mut buf = Vec::with_capacity((end - start + 1) as usize);
        resp.into_reader().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// Rejects URLs whose path ends in a known compression suffix, since we cannot
/// random-access decompressed sectors over HTTP.
///
/// # Errors
/// Returns an error naming the offending suffix.
pub fn reject_if_compressed(url: &str) -> anyhow::Result<()> {
    const COMPRESSED: [&str; 7] = [".xz", ".gz", ".bz2", ".zst", ".lz4", ".lzma", ".lz"];
    // Ignore any query string / fragment when looking at the extension.
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let lower = path.to_ascii_lowercase();
    if let Some(suffix) = COMPRESSED.iter().find(|s| lower.ends_with(**s)) {
        bail!(
            "{url}: compressed images ({suffix}) can't be range-accessed over HTTP; \
             decompress it first (e.g. `xz -d`) and point -f at the raw .img"
        );
    }
    Ok(())
}

/// Probes the server for the image length using a single-byte range request,
/// which also confirms the server honors ranges (status 206 + `Content-Range`).
fn probe_len(agent: &ureq::Agent, url: &str) -> anyhow::Result<u64> {
    let resp = agent.get(url).set("Range", "bytes=0-0").call()?;
    if resp.status() != 206 {
        bail!(
            "server does not support range requests (got status {} for a ranged GET)",
            resp.status()
        );
    }
    // Content-Range: bytes 0-0/<total>
    let cr = resp
        .header("Content-Range")
        .ok_or_else(|| anyhow!("range response missing Content-Range header"))?;
    let total = cr
        .rsplit('/')
        .next()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .ok_or_else(|| anyhow!("unparseable Content-Range: {cr:?}"))?;
    Ok(total)
}
