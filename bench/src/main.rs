use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Parser)]
#[command(name = "nvda-remote-bench", about = "Benchmark NVDA Remote relay servers")]
struct Args {
    /// Server targets as name=host:port (e.g. rust=localhost:6837)
    #[arg(short, long, value_delimiter = ',')]
    targets: Vec<String>,

    /// Number of channel pairs (each pair = 1 master + 1 slave)
    #[arg(short = 'p', long, default_value = "50")]
    pairs: usize,

    /// Number of messages each master sends
    #[arg(short, long, default_value = "200")]
    messages: usize,

    /// Seconds to wait for all pairs to complete
    #[arg(long, default_value = "60")]
    timeout: u64,

    /// Ramp mode: test escalating concurrent sessions to find limits.
    /// Comma-separated pair counts (e.g. 100,500,1000,2000,5000)
    #[arg(long, value_delimiter = ',')]
    ramp: Vec<usize>,
}

struct BenchResult {
    name: String,
    total_messages: u64,
    total_received: u64,
    elapsed: Duration,
    errors: u64,
    latencies_us: Vec<u64>,
}

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    let args = Args::parse();

    if args.targets.is_empty() {
        eprintln!("No targets specified. Example:");
        eprintln!("  bench --targets rust=localhost:6837,python=localhost:6838");
        std::process::exit(1);
    }

    let targets: Vec<(String, String)> = args
        .targets
        .iter()
        .map(|t| {
            let (name, addr) = t.split_once('=').unwrap_or_else(|| {
                eprintln!("Invalid target format: {t}. Use name=host:port");
                std::process::exit(1);
            });
            (name.to_string(), addr.to_string())
        })
        .collect();

    if !args.ramp.is_empty() {
        run_ramp_mode(&targets, &args.ramp, args.messages, args.timeout).await;
    } else {
        run_normal_mode(&targets, args.pairs, args.messages, args.timeout).await;
    }
}

async fn run_normal_mode(
    targets: &[(String, String)],
    pairs: usize,
    messages: usize,
    timeout: u64,
) {
    println!("NVDA Remote Server Benchmark");
    println!("============================");
    println!("Pairs: {pairs}, Messages per master: {messages}");
    println!();

    let mut results = Vec::new();

    for (name, addr) in targets {
        println!("Benchmarking: {name} ({addr})...");
        match run_benchmark(addr, pairs, messages, timeout).await {
            Ok(mut result) => {
                result.name = name.clone();
                print_result(&result);
                results.push(result);
            }
            Err(e) => {
                eprintln!("  ERROR: {e}");
                println!();
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    if results.len() > 1 {
        println!("Comparison");
        println!("----------");
        print_comparison(&results);
    }
}

async fn run_ramp_mode(
    targets: &[(String, String)],
    steps: &[usize],
    messages: usize,
    timeout: u64,
) {
    println!("NVDA Remote Server Concurrency Ramp Test");
    println!("========================================");
    println!("Steps: {steps:?}, Messages per pair: {messages}");
    println!();

    // Header
    print!("{:<20}", "Server");
    for step in steps {
        print!(" {:>12}", format!("{step} pairs"));
    }
    println!();
    println!("{}", "-".repeat(20 + steps.len() * 13));

    for (name, addr) in targets {
        print!("{:<20}", name);
        for &pair_count in steps {
            tokio::time::sleep(Duration::from_secs(2)).await;
            match run_benchmark(addr, pair_count, messages, timeout).await {
                Ok(result) => {
                    let loss_pct = if result.total_messages > 0 {
                        100.0 - (result.total_received as f64 / result.total_messages as f64 * 100.0)
                    } else {
                        100.0
                    };
                    let throughput = if result.elapsed.as_secs_f64() > 0.0 {
                        result.total_received as f64 / result.elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    if result.errors > 0 || loss_pct > 1.0 {
                        print!(" {:>8.0} {:>3}",  throughput, format!("{:.0}%E", loss_pct));
                    } else {
                        print!(" {:>8.0} m/s", throughput);
                    }
                }
                Err(_) => {
                    print!(" {:>12}", "FAIL");
                }
            }
        }
        println!();
    }
}

async fn run_benchmark(
    addr: &str,
    pairs: usize,
    messages_per_master: usize,
    timeout_secs: u64,
) -> Result<BenchResult, String> {
    let tls = make_tls_connector();
    let server_name = make_server_name(addr);

    // Warmup: verify server is reachable
    tls_connect(addr, &tls, &server_name)
        .await
        .map_err(|e| format!("Cannot connect to {addr}: {e}"))?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let errors = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::<u64>::new()));

    let start = Instant::now();
    let mut handles = Vec::new();

    for pair_id in 0..pairs {
        let addr = addr.to_string();
        let tls = tls.clone();
        let sn = server_name.clone();
        let errors = errors.clone();
        let received = received.clone();
        let latencies = latencies.clone();

        handles.push(tokio::spawn(async move {
            let r = run_pair(&addr, &tls, &sn, pair_id, messages_per_master).await;
            match r {
                Ok((recv_count, lats)) => {
                    received.fetch_add(recv_count, Ordering::Relaxed);
                    latencies.lock().await.extend(lats);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        for h in handles {
            let _ = h.await;
        }
    })
    .await;

    let elapsed = start.elapsed();
    let latencies = latencies.lock().await.clone();

    Ok(BenchResult {
        name: String::new(),
        total_messages: (pairs * messages_per_master) as u64,
        total_received: received.load(Ordering::Relaxed),
        elapsed,
        errors: errors.load(Ordering::Relaxed),
        latencies_us: latencies,
    })
}

/// Run a single master/slave pair: connect both, master sends N messages, slave reads them.
async fn run_pair(
    addr: &str,
    tls: &TlsConnector,
    server_name: &ServerName<'static>,
    pair_id: usize,
    messages: usize,
) -> Result<(u64, Vec<u64>), ()> {
    let channel = format!("bench_{pair_id:06}");

    // Connect and join master
    let master = tls_connect(addr, tls, server_name).await.map_err(|_| ())?;
    let (master_read, mut master_write) = tokio::io::split(master);
    let mut master_lines = BufReader::new(master_read).lines();

    send_join(&mut master_write, &channel, "master").await?;
    drain_responses(&mut master_lines, 2).await; // channel_joined + motd

    // Connect and join slave
    let slave = tls_connect(addr, tls, server_name).await.map_err(|_| ())?;
    let (slave_read, mut slave_write) = tokio::io::split(slave);
    let mut slave_lines = BufReader::new(slave_read).lines();

    send_join(&mut slave_write, &channel, "slave").await?;
    drain_responses(&mut slave_lines, 2).await; // channel_joined + motd

    // Master gets client_joined notification for slave
    drain_responses(&mut master_lines, 1).await;

    // Now send messages from master, read from slave
    let mut recv_count = 0u64;
    let mut latencies = Vec::with_capacity(messages);

    for i in 0..messages {
        let msg = format!("{{\"type\":\"key\",\"vk_code\":{i}}}\n");
        let send_time = Instant::now();

        if master_write.write_all(msg.as_bytes()).await.is_err() {
            break;
        }
        if master_write.flush().await.is_err() {
            break;
        }

        match tokio::time::timeout(Duration::from_secs(5), slave_lines.next_line()).await {
            Ok(Ok(Some(_))) => {
                latencies.push(send_time.elapsed().as_micros() as u64);
                recv_count += 1;
            }
            _ => break,
        }
    }

    Ok((recv_count, latencies))
}

async fn send_join<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    channel: &str,
    connection_type: &str,
) -> Result<(), ()> {
    let msg = format!(
        "{{\"type\":\"protocol_version\",\"version\":2}}\n\
         {{\"type\":\"join\",\"channel\":\"{channel}\",\"connection_type\":\"{connection_type}\"}}\n"
    );
    writer.write_all(msg.as_bytes()).await.map_err(|_| ())?;
    writer.flush().await.map_err(|_| ())?;
    Ok(())
}

async fn drain_responses<R: tokio::io::AsyncRead + Unpin>(
    lines: &mut tokio::io::Lines<BufReader<R>>,
    count: usize,
) {
    for _ in 0..count {
        let _ = tokio::time::timeout(Duration::from_secs(2), lines.next_line()).await;
    }
}

async fn tls_connect(
    addr: &str,
    tls: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("TCP connect: {e}"))?;
    tcp.set_nodelay(true).ok();
    tls.connect(server_name.clone(), tcp)
        .await
        .map_err(|e| format!("TLS: {e}"))
}

fn make_server_name(addr: &str) -> ServerName<'static> {
    let host = addr.split(':').next().unwrap_or("localhost");
    ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("localhost".to_string()).unwrap())
}

fn make_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn print_result(r: &BenchResult) {
    let mut sorted = r.latencies_us.clone();
    sorted.sort();

    let throughput = if r.elapsed.as_secs_f64() > 0.0 {
        r.total_received as f64 / r.elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!("  Sent/Received:   {}/{}", r.total_messages, r.total_received);
    println!("  Errors:          {}", r.errors);
    println!("  Elapsed:         {:.2}s", r.elapsed.as_secs_f64());
    println!("  Throughput:      {throughput:.0} msg/s");
    println!(
        "  Latency p50:     {} us",
        percentile(&sorted, 50)
    );
    println!(
        "  Latency p95:     {} us",
        percentile(&sorted, 95)
    );
    println!(
        "  Latency p99:     {} us",
        percentile(&sorted, 99)
    );
    println!();
}

fn print_comparison(results: &[BenchResult]) {
    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Server", "msg/s", "p50 (us)", "p95 (us)", "p99 (us)", "errors"
    );
    println!("{}", "-".repeat(72));
    for r in results {
        let mut sorted = r.latencies_us.clone();
        sorted.sort();
        let throughput = if r.elapsed.as_secs_f64() > 0.0 {
            r.total_received as f64 / r.elapsed.as_secs_f64()
        } else {
            0.0
        };
        println!(
            "{:<20} {:>10.0} {:>10} {:>10} {:>10} {:>10}",
            r.name,
            throughput,
            percentile(&sorted, 50),
            percentile(&sorted, 95),
            percentile(&sorted, 99),
            r.errors,
        );
    }
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (p * sorted.len() / 100).min(sorted.len() - 1);
    sorted[idx]
}
