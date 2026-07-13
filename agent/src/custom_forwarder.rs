use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{self};
use log::{error, info, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTraceData {
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub count: u64,
    pub stime: u64,
    pub timestamp: u64,
    pub comm: String,
    pub process_name: String,
    pub u_stack_id: i32,
    pub k_stack_id: i32,
    pub profiler_type: u8,
    pub stack_data: Vec<u8>,
    pub stack_data_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerPayload {
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: u64,
    pub samples: Vec<StackTraceData>,
}

// Rate-limited error logger
struct RateLimitedLogger {
    last_log: Mutex<Instant>,
    interval: Duration,
    count: AtomicU64,
}

impl RateLimitedLogger {
    fn new(interval: Duration) -> Self {
        Self {
            last_log: Mutex::new(Instant::now() - interval),
            interval,
            count: AtomicU64::new(0),
        }
    }

    fn log_error(&self, msg: &str) {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut last = self.last_log.lock().unwrap();
        if last.elapsed() >= self.interval {
            if count == 1 {
                error!("{}", msg);
            } else {
                error!("[{} consecutive errors] {}", count, msg);
            }
            *last = Instant::now();
            self.count.store(0, Ordering::Relaxed);
        }
    }

    fn reset(&self) {
        self.count.store(0, Ordering::Relaxed);
        let mut last = self.last_log.lock().unwrap();
        *last = Instant::now();
    }
}

// Use LazyLock for static initialization (Rust 1.80+)
// For older Rust versions, use once_cell or lazy_static
static CONNECTION_ERROR_LOGGER: std::sync::LazyLock<RateLimitedLogger> =
    std::sync::LazyLock::new(|| RateLimitedLogger::new(Duration::from_secs(60)));

#[derive(Debug)] 
pub struct CustomForwarder {
    client: Client,
    endpoint: String,
    batch_size: usize,
    flush_interval: Duration,
    buffer: Vec<StackTraceData>,
    sender: mpsc::UnboundedSender<StackTraceData>,
}

impl CustomForwarder {
    pub fn new(endpoint: String, batch_size: usize, flush_interval_secs: u64) -> Arc<Self> {
        let (sender, mut receiver) = mpsc::unbounded_channel::<StackTraceData>();
        
        let forwarder = Arc::new(CustomForwarder {
            client: Client::new(),
            endpoint: endpoint.clone(),
            batch_size,
            flush_interval: Duration::from_secs(flush_interval_secs),
            buffer: Vec::with_capacity(batch_size),
            sender,
        });

        // Spawn the background task with a runtime that lives forever
        let forwarder_clone = forwarder.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async {
                let client = Client::new();
                let mut buffer = Vec::with_capacity(128);
                let mut flush_timer = time::interval(Duration::from_secs(flush_interval_secs));
                
                loop {
                    tokio::select! {
                        Some(data) = receiver.recv() => {
                            buffer.push(data);
                            if buffer.len() >= forwarder_clone.batch_size {
                                if let Err(e) = CustomForwarder::send_batch(&client, &forwarder_clone.endpoint, &buffer).await {
                                    CONNECTION_ERROR_LOGGER.log_error(&format!("Failed to send batch: {}", e));
                                }
                                buffer.clear();
                            }
                        }
                        _ = flush_timer.tick() => {
                            if !buffer.is_empty() {
                                if let Err(e) = CustomForwarder::send_batch(&client, &forwarder_clone.endpoint, &buffer).await {
                                    CONNECTION_ERROR_LOGGER.log_error(&format!("Failed to send batch on timer: {}", e));
                                }
                                buffer.clear();
                            }
                        }
                    }
                }
            });
        });

        info!("Custom forwarder initialized to {}", endpoint);
        forwarder
    }

    pub fn send_data(&self, data: StackTraceData) {
        if let Err(e) = self.sender.send(data) {
            error!("Failed to send data to forwarder channel: {}", e);
        }
    }

    async fn send_batch(
        client: &Client,
        endpoint: &str,
        buffer: &[StackTraceData],
    ) -> Result<(), reqwest::Error> {
        if buffer.is_empty() {
            return Ok(());
        }

        let payload = ProfilerPayload {
            agent_id: std::env::var("AGENT_ID")
                .unwrap_or_else(|_| "unknown".to_string()),
            hostname: hostname::get()
                .map(|h| h.into_string().unwrap_or_else(|_| "unknown".to_string()))
                .unwrap_or_else(|_| "unknown".to_string()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            samples: buffer.to_vec(),
        };

        debug!("Sending {} samples to {}", buffer.len(), endpoint);
        
        match client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                // Reset error counter on success
                CONNECTION_ERROR_LOGGER.reset();
                
                if response.status().is_success() {
                    debug!("Successfully sent {} samples", buffer.len());
                } else {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    error!("Server returned error: {} - {}", status, text);
                }
                Ok(())
            }
            Err(e) => {
                // Error is logged by the caller
                Err(e)
            }
        }
    }
}