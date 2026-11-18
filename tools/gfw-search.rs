//! OpenGFW FET offline evaluator + evasion-prefix search facility.
//!
//! The FET ("Fully Encrypted Traffic") analyzer here is a line-by-line port of
//! OpenGFW's `analyzer/tcp/fet.go` (HyNetworks/OpenGFW), which implements the
//! detection algorithm inferred in "How the Great Firewall of China Detects
//! and Blocks Fully Encrypted Traffic" (USENIX Security 2023).
//!
//! Live OpenGFW requires NFQueue (root + kernel modules) and is unavailable in
//! most dev environments. This tool evaluates the *same* 5 exemption rules on
//! captured first TCP payloads, and searches for random prefix generators that
//! make a ShadowLemon-style high-entropy first packet exempt.
//!
//! Build: rustc -O tools/gfw-search.rs -o /tmp/opencode/gfw-search
//! Usage:
//!   gfw-search check <pcap> [ports...]
//!   gfw-search search <pcap> [generations] [population]
//!
//! No external crates; std only. Keep the repository Go-free.

use std::collections::BTreeMap;
use std::env;
use std::fs;

// ---------------- OpenGFW FET analyzer (port of fet.go) ----------------

/// Average popcount per byte (Ex1). Exempt when <= 3.4 or >= 4.6.
fn average_popcount(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let total: usize = data.iter().map(|b| b.count_ones() as usize).sum();
    total as f32 / data.len() as f32
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// First six bytes printable ASCII (Ex2).
fn first_six_printable(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6].iter().all(|&b| is_printable(b))
}

/// Fraction of printable bytes (Ex3). Exempt when > 0.5.
fn printable_fraction(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().filter(|&&b| is_printable(b)).count() as f32 / data.len() as f32
}

/// Longest run of consecutive printable bytes (Ex4). Exempt when > 20.
fn contiguous_printable(data: &[u8]) -> usize {
    let (mut best, mut cur) = (0, 0);
    for &b in data {
        if is_printable(b) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// TLS / HTTP first-bytes match (Ex5), exactly as OpenGFW implements it.
fn is_tls_or_http(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }
    if (0x16..=0x17).contains(&data[0]) && data[1] == 0x03 && data[2] <= 0x09 {
        return true;
    }
    matches!(
        &data[..3],
        b"GET" | b"HEA" | b"POS" | b"PUT" | b"DEL" | b"CON" | b"OPT" | b"TRA" | b"PAT"
    )
}

#[derive(Debug, Clone, Copy)]
struct Verdict {
    ex1: f32,
    ex2: bool,
    ex3: f32,
    ex4: usize,
    ex5: bool,
    /// OpenGFW's `yes` property: true means "this is fully encrypted" -> BLOCK.
    detected: bool,
}

fn fet(data: &[u8]) -> Verdict {
    let ex1 = average_popcount(data);
    let ex2 = first_six_printable(data);
    let ex3 = printable_fraction(data);
    let ex4 = contiguous_printable(data);
    let ex5 = is_tls_or_http(data);
    let exempt = ex1 <= 3.4 || ex1 >= 4.6 || ex2 || ex3 > 0.5 || ex4 > 20 || ex5;
    Verdict { ex1, ex2, ex3, ex4, ex5, detected: !exempt }
}

// ---------------- pcap reading (classic pcap, no deps) ----------------

fn read_pcap(path: &str) -> Vec<Vec<u8>> {
    let raw = match fs::read(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return Vec::new();
        }
    };
    if raw.len() < 24 {
        return Vec::new();
    }
    let little = raw[..4] == [0xd4, 0xc3, 0xb2, 0xa1];
    let u32at = |b: &[u8]| -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if little { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) }
    };
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= raw.len() {
        let incl = u32at(&raw[off + 8..off + 12]) as usize;
        off += 16;
        if off + incl > raw.len() {
            break;
        }
        out.push(raw[off..off + incl].to_vec());
        off += incl;
    }
    out
}

fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Extract the first client->server TCP payload of each connection whose
/// destination port is in `ports`.
fn first_payloads(packets: &[Vec<u8>], ports: &[u16]) -> Vec<Vec<u8>> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for d in packets {
        if d.len() < 14 || u16be(&d[12..14]) != 0x0800 {
            continue;
        }
        let ip = &d[14..];
        if ip.len() < 20 || ip[9] != 6 {
            continue;
        }
        let ihl = (ip[0] & 0x0f) as usize * 4;
        if ip.len() < ihl + 20 {
            continue;
        }
        let l4 = &ip[ihl..];
        let sp = u16be(&l4[..2]);
        let dp = u16be(&l4[2..4]);
        let doff = (l4[12] >> 4) as usize * 4;
        let total = u16be(&ip[2..4]) as usize;
        if total <= ihl + doff || ip.len() < total {
            continue;
        }
        let payload = &l4[doff..total - ihl];
        if !ports.contains(&dp) || payload.is_empty() {
            continue;
        }
        if seen.insert((sp, dp)) {
            out.push(payload.to_vec());
        }
    }
    out
}

// ---------------- prefix generators (the search space) ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Printable,
    LowPop,
    HighPop,
    Tls,
    Http,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Kind::Printable => "printable",
            Kind::LowPop => "low-popcount",
            Kind::HighPop => "high-popcount",
            Kind::Tls => "tls-magic",
            Kind::Http => "http-method",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Candidate {
    kind: Kind,
    len: usize,
}

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// Build a concrete prefix from a candidate. Prefix bytes are random per
/// instance so a shipped generator never produces a fixed signature.
fn build_prefix(c: Candidate, rng: &mut Rng) -> Vec<u8> {
    match c.kind {
        Kind::Printable => (0..c.len).map(|_| (0x20 + rng.below(0x5f)) as u8).collect(),
        Kind::LowPop => (0..c.len)
            .map(|_| {
                loop {
                    let b = rng.byte();
                    if b.count_ones() <= 2 {
                        return b;
                    }
                }
            })
            .collect(),
        Kind::HighPop => (0..c.len)
            .map(|_| {
                loop {
                    let b = rng.byte();
                    if b.count_ones() >= 6 {
                        return b;
                    }
                }
            })
            .collect(),
        Kind::Tls => vec![0x16, 0x03, 0x01],
        Kind::Http => {
            let methods: [&[u8]; 5] = [b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS"];
            let m = methods[rng.below(methods.len())];
            let mut v = m.to_vec();
            v.extend(std::iter::repeat_with(|| rng.byte()).take(c.len.saturating_sub(m.len())));
            v
        }
    }
}

/// A candidate is "robust" only when EVERY randomized instance evades FET on
/// EVERY sampled first packet. Evaluating against multiple templates avoids
/// reporting template-specific luck (e.g. a 4-byte printable prefix that only
/// works because this particular nonce happened to start with two printable
/// bytes).
fn evaluate(
    c: Candidate,
    templates: &[Vec<u8>],
    trials: usize,
    rng: &mut Rng,
) -> (usize, usize, Verdict) {
    let mut wins = 0;
    let total = templates.len() * trials;
    let mut last = fet(&templates[0]);
    for template in templates {
        for _ in 0..trials {
            let mut frame = build_prefix(c, rng);
            frame.extend_from_slice(template);
            last = fet(&frame);
            if !last.detected {
                wins += 1;
            }
        }
    }
    (wins, total, last)
}

// ---------------- commands ----------------

fn cmd_check(pcap: &str, ports: &[u16]) {
    let packets = read_pcap(pcap);
    let payloads = first_payloads(&packets, ports);
    println!("OpenGFW FET check: {pcap}");
    println!("first client payloads: {}", payloads.len());
    if payloads.is_empty() {
        return;
    }
    let mut blocked = 0;
    let mut exempted = 0;
    for p in &payloads {
        let v = fet(p);
        if v.detected {
            blocked += 1;
        } else {
            exempted += 1;
        }
    }
    println!("BLOCK (detected as fully encrypted): {blocked}");
    println!("EXEMPT: {exempted}");
    let v = fet(&payloads[0]);
    println!(
        "sample[0]: len={} ex1={:.3} ex2={} ex3={:.3} ex4={} ex5={} -> {}",
        payloads[0].len(), v.ex1, v.ex2, v.ex3, v.ex4, v.ex5,
        if v.detected { "BLOCK" } else { "EXEMPT" }
    );
}

fn cmd_search(pcap: &str, generations: usize, population: usize) {
    let packets = read_pcap(pcap);
    let payloads = first_payloads(&packets, &DEFAULT_PORTS);
    if payloads.is_empty() {
        eprintln!("no first client payload found in {pcap}");
        return;
    }
    // Validate against a spread of real first packets, not one lucky sample.
    let templates: Vec<Vec<u8>> = payloads.iter().step_by(3).cloned().collect();
    println!("OpenGFW FET prefix search");
    println!("templates: {} first packets from {pcap}", templates.len());
    println!("baseline: {:?}", fet(&templates[0]));

    let mut rng = Rng::new(0x5eed_1234_5678_9abc);
    let mut pool: Vec<Candidate> = Vec::new();
    let kinds = [Kind::Printable, Kind::LowPop, Kind::HighPop, Kind::Tls, Kind::Http];
    for _ in 0..generations {
        for _ in 0..population {
            let kind = kinds[rng.below(kinds.len())];
            let len = 1 + rng.below(48);
            pool.push(Candidate { kind, len });
        }
    }
    // Score: robustness first, then shorter prefix.
    let mut ranked: Vec<(f64, Candidate, usize, usize, Verdict)> = Vec::new();
    let trials = 4;
    for c in pool {
        let (wins, total, v) = evaluate(c, &templates, trials, &mut rng);
        if wins != total {
            continue; // require every instance on every template to evade
        }
        let score = wins as f64 * 1000.0 - c.len as f64 * 2.0;
        ranked.push((score, c, wins, total, v));
    }
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    ranked.dedup_by(|a, b| a.1 == b.1);

    // Keep the shortest robust strategy per kind so the user gets a menu.
    let mut best: BTreeMap<Kind, (f64, Candidate, usize, usize, Verdict)> = BTreeMap::new();
    for entry in ranked {
        best.entry(entry.1.kind).or_insert(entry);
    }
    println!(
        "\nrobust strategies (all randomized instances evaded FET on all {} templates):",
        templates.len()
    );
    for (kind, (score, c, wins, total, v)) in best {
        let mut rng2 = Rng::new(0xabcd_ef01_2345_6789);
        let sample = build_prefix(c, &mut rng2);
        println!(
            "- {kind}: len={} score={score:.0} wins={wins}/{total} ex1={:.3} ex2={} ex3={:.3} ex4={} ex5={}",
            c.len, v.ex1, v.ex2, v.ex3, v.ex4, v.ex5
        );
        println!("  sample prefix (hex): {}", hex(&sample));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

const DEFAULT_PORTS: [u16; 5] = [9999, 10000, 10001, 10002, 10003];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gfw-search check <pcap> [ports...] | search <pcap> [generations] [population]");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "check" => {
            let ports: Vec<u16> = if args.len() > 3 {
                args[3..].iter().filter_map(|s| s.parse().ok()).collect()
            } else {
                DEFAULT_PORTS.to_vec()
            };
            cmd_check(&args[2], &ports);
        }
        "search" => {
            let generations = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8);
            let population = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(64);
            cmd_search(&args[2], generations, population);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }
}
