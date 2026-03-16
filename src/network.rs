use std::net::{TcpStream, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};

pub fn detect_adapter() -> Option<String> {
    let output = Command::new("powershell")
        .args([
            "-Command",
            "(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name",
        ])
        .output()
        .ok()?;

    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub fn get_current_dns() -> Option<String> {
    let output = Command::new("powershell")
        .args([
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object -First 1 -ExpandProperty ServerAddresses | Out-String",
        ])
        .output()
        .ok()?;

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if result.is_empty() {
        Some("Не определено".to_string())
    } else {
        Some(result.replace('\n', ", ").replace('\r', ""))
    }
}

pub fn ping_host(ip: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "3000", ip])
        .output();

    match output {
        Ok(out) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ok = out.status.success() && (stdout.contains("TTL=") || stdout.contains("ttl="));

            if ok {
                // Try to extract actual time from ping output
                if let Some(time_str) = extract_ping_time(&stdout) {
                    (true, Some(time_str))
                } else {
                    (true, Some(elapsed))
                }
            } else {
                (false, None)
            }
        }
        Err(_) => (false, None),
    }
}

fn extract_ping_time(output: &str) -> Option<u64> {
    // Match patterns like "time=46ms" or "time<1ms" or "время=46мс"
    for line in output.lines() {
        let lower = line.to_lowercase();
        if let Some(pos) = lower.find("time=").or_else(|| lower.find("time<")) {
            let after = &lower[pos + 5..];
            let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ms) = num.parse::<u64>() {
                return Some(ms);
            }
        }
        // Russian locale
        if let Some(pos) = lower.find("=").filter(|_| lower.contains("ms") || lower.contains("мс")) {
            let after = &lower[pos + 1..];
            let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ms) = num.parse::<u64>() {
                if ms < 10000 {
                    return Some(ms);
                }
            }
        }
    }
    None
}

pub fn tcp_check(ip: &str, port: u16) -> (bool, Option<u64>) {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().unwrap();
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_stream) => {
            let elapsed = start.elapsed().as_millis() as u64;
            (true, Some(elapsed))
        }
        Err(_) => (false, None),
    }
}

pub fn https_check(url: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build();

    match client {
        Ok(c) => match c.get(url).send() {
            Ok(resp) => {
                let elapsed = start.elapsed().as_millis() as u64;
                (resp.status().is_success(), Some(elapsed))
            }
            Err(_) => (false, None),
        },
        Err(_) => (false, None),
    }
}

/// Benchmarks Telegram connectivity: runs multiple TCP+HTTPS checks,
/// returns (works: bool, score: u64) where lower score = faster connection.
/// Score is average latency across all successful checks. u64::MAX if nothing works.
pub fn benchmark_telegram() -> (bool, u64) {
    let tcp_targets = [
        ("149.154.167.51", 443u16),
        ("149.154.175.50", 443),
        ("149.154.167.91", 443),
        ("91.108.56.100", 443),
    ];

    let mut total_ms: u64 = 0;
    let mut ok_count: u64 = 0;
    let mut fail_count: u64 = 0;

    // TCP checks (x2 rounds for stability)
    for _ in 0..2 {
        for (ip, port) in &tcp_targets {
            let (ok, latency) = tcp_check(ip, *port);
            if ok {
                total_ms += latency.unwrap_or(5000);
                ok_count += 1;
            } else {
                fail_count += 1;
            }
        }
    }

    // HTTPS check — the real indicator of usable speed
    let https_urls = [
        "https://web.telegram.org",
        "https://t.me",
    ];
    for url in &https_urls {
        let (ok, latency) = https_check(url);
        if ok {
            // Weight HTTPS 3x heavier since it's closer to real usage
            let ms = latency.unwrap_or(10000);
            total_ms += ms * 3;
            ok_count += 3;
        } else {
            fail_count += 3;
        }
    }

    if ok_count == 0 {
        return (false, u64::MAX);
    }

    // Penalize failures: each fail adds 2000ms to the score
    let penalty = fail_count * 2000;
    let avg = (total_ms + penalty) / (ok_count + fail_count);

    (true, avg)
}
