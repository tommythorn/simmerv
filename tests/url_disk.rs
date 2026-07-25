//! Integration test for the URL-backed block storage.
//!
//! A minimal in-process HTTP server serves a small "disk image" with range
//! support, so we can exercise the real fetch path (range parsing, block
//! caching, copy-on-write) without any external network.

use simmerv::device::url_disk::UrlStorage;
use simmerv::device::url_disk::reject_if_compressed;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread;

const SECTOR: usize = 512;

/// Build a 3-sector image where sector `i` is filled with byte `0xA0 + i`.
fn make_image() -> Vec<u8> {
    let mut img = Vec::with_capacity(3 * SECTOR);
    for b in [0xA0u8, 0xA1, 0xA2] {
        img.extend_from_slice(&[b; SECTOR]);
    }
    img
}

/// Serve `image` over HTTP with byte-range support on an ephemeral port.
/// Returns the base URL and a counter of range requests actually served.
fn serve(image: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}/img", listener.local_addr().expect("addr"));
    let range_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&range_hits);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let _ = handle(stream, &image, &hits);
        }
    });

    (url, range_hits)
}

fn handle(stream: TcpStream, image: &[u8], hits: &AtomicUsize) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // Parse request headers; capture the Range if present.
    let mut range = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(()); // client hung up
        }
        let line = line.trim_end();
        if line.is_empty() {
            break; // end of headers
        }
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("range:") {
            if let Some(spec) = rest.trim().strip_prefix("bytes=") {
                let mut parts = spec.split('-');
                let a: u64 = parts
                    .next()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                let b: u64 = parts
                    .next()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(image.len() as u64 - 1);
                range = Some((a, b));
            }
        }
    }

    let total = image.len() as u64;
    if let Some((a, b)) = range {
        hits.fetch_add(1, Ordering::Relaxed);
        let b = b.min(total - 1);
        let body = &image[a as usize..=b as usize];
        write!(
            writer,
            "HTTP/1.1 206 Partial Content\r\n\
             Content-Range: bytes {a}-{b}/{total}\r\n\
             Content-Length: {}\r\n\
             Accept-Ranges: bytes\r\n\
             Connection: close\r\n\r\n",
            body.len(),
        )?;
        writer.write_all(body)?;
    } else {
        write!(
            writer,
            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
             Accept-Ranges: bytes\r\nConnection: close\r\n\r\n",
        )?;
        writer.write_all(image)?;
    }
    Ok(())
}

fn read_sector(disk: &UrlStorage, sector: usize) -> Vec<u8> {
    let mut buf = vec![0u8; SECTOR];
    disk.read_at((sector * SECTOR) as u64, &mut buf);
    buf
}

/// Reads pull from the URL, get cached per block, and writes stay local
/// (copy-on-write) without touching the base image.
#[test]
fn url_disk_reads_cache_and_writes_are_local() {
    let (url, hits) = serve(make_image());
    let mut disk = UrlStorage::open(&url).expect("open url disk");

    // Size comes from the probe (Content-Range total); one range hit so far.
    assert_eq!(disk.sector_count(), 3);
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "probe should be one request"
    );

    // First base read fetches the (single) 1 MiB block covering the image.
    assert_eq!(read_sector(&disk, 2), vec![0xA2; SECTOR]);
    assert_eq!(
        hits.load(Ordering::Relaxed),
        2,
        "one block fetch after probe"
    );

    // A second base read hits the cached block: no new request.
    assert_eq!(read_sector(&disk, 0), vec![0xA0; SECTOR]);
    assert_eq!(hits.load(Ordering::Relaxed), 2, "block should be cached");

    // Write sector 1 locally; a full-sector write needs no base fetch.
    disk.write_at(SECTOR as u64, &[0x55; SECTOR]);
    assert_eq!(hits.load(Ordering::Relaxed), 2, "write must not fetch");

    // Overlay wins for the written sector; other sectors still read the base.
    assert_eq!(
        read_sector(&disk, 1),
        vec![0x55; SECTOR],
        "overlay read-back"
    );
    assert_eq!(read_sector(&disk, 0), vec![0xA0; SECTOR], "base untouched");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        2,
        "all served from cache/overlay"
    );
}

/// Compressed and non-http URLs are rejected before any network access.
#[test]
fn compressed_and_bad_scheme_urls_are_rejected() {
    for bad in [
        "https://host/ubuntu.img.xz",
        "https://host/ubuntu.img.gz",
        "https://host/ubuntu.IMG.ZST",
        "https://host/ubuntu.img.xz?sig=abc",
    ] {
        assert!(
            reject_if_compressed(bad).is_err(),
            "{bad} should be rejected"
        );
        assert!(
            UrlStorage::open(bad).is_err(),
            "{bad} open should fail offline"
        );
    }

    for ok in ["https://host/ubuntu.img", "https://host/disk.img?token=1"] {
        assert!(reject_if_compressed(ok).is_ok(), "{ok} should be allowed");
    }

    assert!(
        UrlStorage::open("ftp://host/disk.img").is_err(),
        "non-http scheme should be rejected offline"
    );
}
