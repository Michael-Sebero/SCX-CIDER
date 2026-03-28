// SPDX-License-Identifier: GPL-2.0
// scx_imperator - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling

mod calibrate;
mod stats;
mod topology;
mod tui;

use core::sync::atomic::Ordering;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{info, warn};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    Esports,
    Legacy,
    Gaming,
    Default,
}

impl Profile {
    fn values(&self) -> (u64, u64, u64) {
        match self {
            Profile::Esports => (1000, 4000, 50000),
            Profile::Legacy  => (4000, 12000, 200000),
            Profile::Gaming  => (2000, 8000, 100000),
            Profile::Default => Profile::Gaming.values(),
        }
    }

    fn starvation_threshold(&self) -> [u64; 8] {
        match self {
            Profile::Esports => [
                1_500_000, 4_000_000, 20_000_000, 50_000_000,
                50_000_000, 50_000_000, 50_000_000, 50_000_000,
            ],
            Profile::Legacy => [
                6_000_000, 16_000_000, 80_000_000, 200_000_000,
                200_000_000, 200_000_000, 200_000_000, 200_000_000,
            ],
            Profile::Gaming | Profile::Default => [
                3_000_000, 8_000_000, 40_000_000, 100_000_000,
                100_000_000, 100_000_000, 100_000_000, 100_000_000,
            ],
        }
    }

    fn tier_multiplier(&self) -> [u32; 8] {
        match self {
            Profile::Esports => [256, 1024, 2048, 4095, 4095, 4095, 4095, 4095],
            Profile::Gaming | Profile::Default => [512, 1024, 2048, 4095, 4095, 4095, 4095, 4095],
            Profile::Legacy => [768, 1024, 1536, 2048, 2048, 2048, 2048, 2048],
        }
    }

    fn wait_budget(&self) -> [u64; 8] {
        match self {
            Profile::Esports => [50_000, 1_000_000, 4_000_000, 0, 0, 0, 0, 0],
            Profile::Legacy  => [200_000, 4_000_000, 16_000_000, 0, 0, 0, 0, 0],
            Profile::Gaming | Profile::Default => [100_000, 2_000_000, 8_000_000, 0, 0, 0, 0, 0],
        }
    }

    fn tier_configs(&self, quantum_us: u64, starvation_override: Option<u64>) -> [u64; 8] {
        let base_starvation = self.starvation_threshold();
        let multiplier = self.tier_multiplier();
        let budget = self.wait_budget();

        let starvation: [u64; 8] = if let Some(cli_us) = starvation_override {
            let cli_ns = cli_us * 1000;
            let default_t3 = base_starvation[3];
            if default_t3 > 0 {
                base_starvation.map(|s| s * cli_ns / default_t3)
            } else {
                base_starvation
            }
        } else {
            base_starvation
        };

        let mut configs = [0u64; 8];
        for i in 0..8 {
            let quantum_kns = (quantum_us * 1000) >> 10;
            configs[i] = (multiplier[i] as u64 & 0xFFF)
                | ((quantum_kns & 0xFFFF) << 12)
                | (((budget[i] >> 10) & 0xFFFF) << 28)
                | (((starvation[i] >> 10) & 0xFFFFF) << 44);
        }
        configs
    }
}

/// 🍰 scx_imperator: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// 4-TIER SYSTEM (classified by avg_runtime):
///   T0 Critical  (<100µs): IRQ, input, audio, network
///   T1 Interact  (<2ms):   compositor, physics, AI
///   T2 Frame     (<8ms):   game render, encoding
///   T3 Bulk      (≥8ms):   compilation, background
#[derive(Parser, Debug)]
#[command(author, version, about = "🍰 scx_imperator scheduler", verbatim_doc_comment)]
struct Args {
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming)]
    profile: Profile,
    #[arg(long)]
    quantum: Option<u64>,
    #[arg(long)]
    new_flow_bonus: Option<u64>,
    #[arg(long)]
    starvation: Option<u64>,
    #[arg(long, short)]
    verbose: bool,
    #[arg(long, default_value_t = 1)]
    interval: u64,
}

impl Args {
    fn effective_values(&self) -> (u64, u64, u64) {
        let (q, nfb, starv) = self.profile.values();
        (
            self.quantum.unwrap_or(q),
            self.new_flow_bonus.unwrap_or(nfb),
            self.starvation.unwrap_or(starv),
        )
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
    latency_matrix: Arc<Mutex<Vec<Vec<f64>>>>,
    /// eventfd read end: fires once when ETD calibration completes.
    /// -1 if creation failed (non-fatal: falls back to 60 s timeout polling).
    etd_efd: i32,
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if self.etd_efd >= 0 {
            unsafe { libc::close(self.etd_efd) };
        }
    }
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        scx_utils::import_enums!(open_skel);

        let topo = topology::detect()?;
        let (quantum, new_flow_bonus, _) = args.effective_values();

        // ── eventfd for ETD completion notification ───────────────────────
        // The background thread writes to this fd when calibration finishes.
        // The event loop polls [signalfd, etd_efd] and shrinks to [signalfd]
        // after the eventfd fires — matching s6's dynamic poll-set pattern.
        //
        // EFD_NONBLOCK: read() returns EAGAIN instead of blocking when empty.
        // EFD_CLOEXEC:  not inherited across exec.
        let etd_efd = unsafe {
            libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)
        };
        if etd_efd < 0 {
            warn!(
                "Failed to create ETD eventfd ({}), falling back to 60s timeout polling",
                std::io::Error::last_os_error()
            );
        }

        // Duplicate the fd for the background thread (write end).
        // Scheduler owns etd_efd (read, closed in Drop).
        // Thread owns etd_efd_write (write, closed by thread after signalling).
        let etd_efd_write = if etd_efd >= 0 {
            let fd = unsafe { libc::dup(etd_efd) };
            if fd < 0 {
                warn!("dup(etd_efd) failed — falling back to timeout polling");
                -1i32
            } else {
                fd
            }
        } else {
            -1i32
        };

        info!("Starting ETD calibration in background...");
        let nr_cpus_cal = topo.nr_cpus;
        let latency_matrix = Arc::new(Mutex::new(vec![vec![0.0f64; nr_cpus_cal]; nr_cpus_cal]));
        let matrix_bg = latency_matrix.clone();
        let is_verbose = args.verbose;

        std::thread::spawn(move || {
            let result = calibrate::calibrate_full_matrix(
                nr_cpus_cal,
                &calibrate::EtdConfig::default(),
                |current, total, is_complete| {
                    if !is_verbose {
                        tui::render_calibration_progress(current, total, is_complete);
                    }
                },
            );
            match matrix_bg.lock() {
                Ok(mut m)  => *m = result,
                Err(e)     => *e.into_inner() = result,
            }
            // Signal ETD completion.  The event loop wakes within microseconds
            // and writes the LLC cost table — not up to 1 second later.
            if etd_efd_write >= 0 {
                let val: u64 = 1;
                unsafe {
                    libc::write(
                        etd_efd_write,
                        &val as *const u64 as *const libc::c_void,
                        8,
                    );
                    libc::close(etd_efd_write);
                }
            }
        });

        // Configure BPF rodata
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns       = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            rodata.enable_stats     = args.verbose;
            rodata.tier_configs     = args.profile.tier_configs(quantum, args.starvation);
            rodata.has_hybrid       = topo.has_hybrid_cores;

            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(64) as u32;
            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
            // NOTE: llc_cpu_mask is NOT written from Rust.
            // imperator_init (BPF side) computes it from cpu_llc_id at scheduler
            // attachment time — before any task is scheduled.  This eliminates
            // the partial-deploy hazard where a missing write left the mask
            // all-zeros, causing silent kick failures.
        }

        let skel = open_skel.load().context("Failed to load BPF program")?;

        Ok(Self { skel, args, topology: topo, latency_matrix, etd_efd })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let _link = self
            .skel
            .maps
            .imperator_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        self.show_startup_splash()?;

        let mut etd_written = self.try_write_etd_costs();

        if self.args.verbose {
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
            )?;
        } else {
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGINT);
            mask.add(Signal::SIGTERM);
            mask.thread_block().context("Failed to block signals")?;

            let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)
                .context("Failed to create signalfd")?;

            use nix::poll::{poll, PollFd, PollFlags};
            use std::os::fd::BorrowedFd;

            // Build a fixed-size poll array.  fds[0] = signalfd (always polled).
            // fds[1] = etd_efd when available, else signalfd again as a dummy
            // (safe: n_fds == 1 when etd_efd < 0, so fds[1] is never passed to poll).
            //
            // Constructing both entries from raw fds avoids moving signal_pfd
            // into the else-arm before using it in the array (PollFd is not Copy).
            let active_etd_fd = if self.etd_efd >= 0 { self.etd_efd } else { sfd.as_raw_fd() };
            let mut fds = unsafe {
                [
                    PollFd::new(BorrowedFd::borrow_raw(sfd.as_raw_fd()), PollFlags::POLLIN),
                    PollFd::new(BorrowedFd::borrow_raw(active_etd_fd),   PollFlags::POLLIN),
                ]
            };

            loop {
                // Dynamic fd count: mirrors s6's `iopause_g(x, 2 + (notifyfd >= 0))`.
                // After ETD fires (etd_written=true) or if the fd is unavailable,
                // shrink to 1 — steady state polls only the signalfd.
                let n_fds: usize = if etd_written || self.etd_efd < 0 { 1 } else { 2 };

                let result = poll(&mut fds[..n_fds], nix::poll::PollTimeout::from(60_000u16));

                match result {
                    Ok(n) if n > 0 => {
                        // Check etd eventfd first (non-blocking — EAGAIN if signalfd-only event).
                        if !etd_written && self.etd_efd >= 0 {
                            let mut val = 0u64;
                            let r = unsafe {
                                libc::read(
                                    self.etd_efd,
                                    &mut val as *mut u64 as *mut libc::c_void,
                                    8,
                                )
                            };
                            if r == 8 {
                                etd_written = self.try_write_etd_costs();
                                if !etd_written {
                                    warn!("ETD eventfd fired but matrix still empty — will retry at next timeout");
                                }
                            }
                        }

                        // Check signalfd.
                        match sfd.read_signal() {
                            Ok(Some(siginfo)) => {
                                // Exhaustive match — unexpected signals are programming errors.
                                match siginfo.ssi_signo as i32 {
                                    libc::SIGINT | libc::SIGTERM => {
                                        info!("Received signal {} — shutting down", siginfo.ssi_signo);
                                        shutdown.store(true, Ordering::Relaxed);
                                    }
                                    other => {
                                        warn!("Unexpected signal {} on signalfd — this is a bug", other);
                                    }
                                }
                                break;
                            }
                            Ok(None) | Err(nix::errno::Errno::EAGAIN) => {
                                // signalfd not ready — only ETD fd fired; continue.
                            }
                            Err(e) => {
                                warn!("read_signal error: {}", e);
                                break;
                            }
                        }
                    }
                    Ok(_) => {
                        // 60 s timeout: retry ETD write (covers eventfd-unavailable path)
                        // and check for BPF scheduler exit via UEI.
                        if !etd_written {
                            etd_written = self.try_write_etd_costs();
                        }
                        if scx_utils::uei_exited!(&self.skel, uei) {
                            match scx_utils::uei_report!(&self.skel, uei) {
                                Ok(reason) => warn!("BPF scheduler exited: {:?}", reason),
                                Err(e)     => warn!("BPF scheduler exited (reason unavailable: {})", e),
                            }
                            break;
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {
                        if shutdown.load(Ordering::Relaxed) { break; }
                    }
                    Err(e) => {
                        warn!("poll() error: {}", e);
                        break;
                    }
                }
            }
        }

        info!("scx_imperator scheduler shutting down");
        Ok(())
    }

    /// Compress the ETD matrix into per-LLC-pair costs and write to BPF BSS.
    ///
    /// Returns true when data was written, false when calibration is still
    /// in progress (matrix all-zeros) or the mutex is contested.
    ///
    /// Uses try_lock() so a contested mutex causes a fast retry at the next
    /// wakeup rather than blocking the event loop.  With the eventfd mechanism,
    /// the thread releases the mutex before firing the fd, so contention in
    /// practice is impossible — try_lock() is defense-in-depth.
    fn try_write_etd_costs(&mut self) -> bool {
        let matrix = match self.latency_matrix.try_lock() {
            Ok(m)  => m.clone(),
            Err(_) => return false,
        };

        if !matrix.iter().flatten().any(|&v| v > 0.0) {
            return false;
        }

        let nr_cpus = matrix.len().min(topology::MAX_CPUS);
        let nr_llcs = self
            .topology
            .llc_cpu_mask
            .iter()
            .filter(|&&m| m != 0)
            .count()
            .min(topology::MAX_LLCS);

        let matrix_ref = &matrix;

        if let Some(bss) = &mut self.skel.maps.bss_data {
            for llc_a in 0..nr_llcs {
                for llc_b in 0..nr_llcs {
                    if llc_a == llc_b { continue; }
                    let min_ns = (0..nr_cpus)
                        .filter(|&ca| self.topology.cpu_llc_id[ca] as usize == llc_a)
                        .flat_map(|ca| {
                            (0..nr_cpus)
                                .filter(|&cb| self.topology.cpu_llc_id[cb] as usize == llc_b)
                                .filter_map(move |cb| {
                                    let v = matrix_ref[ca][cb];
                                    if v > 0.0 { Some(v) } else { None }
                                })
                        })
                        .fold(f64::MAX, f64::min);

                    let cost: u8 = if min_ns == f64::MAX {
                        0
                    } else {
                        ((min_ns / 4.0) as u64).min(255) as u8
                    };
                    bss.llc_etd_cost[llc_a][llc_b] = cost;
                }
            }
            info!("ETD: LLC cost table written ({} LLCs)", nr_llcs);
        }
        true
    }

    fn show_startup_splash(&self) -> Result<()> {
        let (q, _nfb, starv) = self.args.effective_values();
        let profile_str = format!("{:?}", self.args.profile).to_uppercase();
        let matrix = self
            .latency_matrix
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        tui::render_startup_screen(tui::StartupParams {
            topology: &self.topology,
            latency_matrix: &matrix,
            profile: &profile_str,
            quantum: q,
            starvation: starv,
        })
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut open_object = std::mem::MaybeUninit::uninit();
    let mut scheduler = Scheduler::new(args, &mut open_object)?;
    scheduler.run(shutdown)?;
    Ok(())
}
