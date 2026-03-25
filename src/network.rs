use std::net::{TcpStream, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};

// ===== Adapter detection =====

#[cfg(target_os = "windows")]
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

#[cfg(not(target_os = "windows"))]
pub fn detect_adapter() -> Option<String> {
    // Parse default route: "default via 10.0.0.1 dev eth0 ..."
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(pos) = line.find("dev ") {
            let after = &line[pos + 4..];
            let iface = after.split_whitespace().next()?;
            return Some(iface.to_string());
        }
    }
    None
}

// ===== Current DNS =====

#[cfg(target_os = "windows")]
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

#[cfg(not(target_os = "windows"))]
pub fn get_current_dns() -> Option<String> {
    let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let servers: Vec<&str> = content
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();

    if servers.is_empty() {
        Some("Не определено".to_string())
    } else {
        Some(servers.join(", "))
    }
}

// ===== Ping =====

#[cfg(target_os = "windows")]
pub fn ping_host(ip: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    let output = Command::new("ping")
        .args(["-n", "1", "-w", "3000", ip])
        .output();

    parse_ping_output(output, start)
}

#[cfg(not(target_os = "windows"))]
pub fn ping_host(ip: &str) -> (bool, Option<u64>) {
    let start = Instant::now();
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "3", ip])
        .output();

    parse_ping_output(output, start)
}

fn parse_ping_output(
    output: Result<std::process::Output, std::io::Error>,
    start: Instant,
) -> (bool, Option<u64>) {
    match output {
        Ok(out) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let stdout = String::from_utf8_lossy(&out.stdout);
            let ok = out.status.success()
                && (stdout.contains("TTL=") || stdout.contains("ttl="));

            if ok {
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

// ===== TCP / HTTPS checks (cross-platform) =====

pub fn tcp_check(ip: &str, port: u16) -> (bool, Option<u64>) {
    let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
        Ok(a) => a,
        Err(_) => return (false, None),
    };
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

    let https_urls = [
        "https://web.telegram.org",
        "https://t.me",
    ];
    for url in &https_urls {
        let (ok, latency) = https_check(url);
        if ok {
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

    let penalty = fail_count * 2000;
    let avg = (total_ms + penalty) / (ok_count + fail_count);

    (true, avg)
}
