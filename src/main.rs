// SPDX-License-Identifier: GPL-2.0
// scx_cider - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling

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
// Include the generated interface bindings
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

// Include the generated BPF skeleton
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

/// Scheduler profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Ultra-low-latency for competitive esports (1ms quantum)
    Esports,
    /// Optimized for older/lower-power hardware (4ms quantum)
    Legacy,
    /// Low-latency profile optimized for gaming and interactive workloads
    Gaming,
    /// Balanced profile for general desktop use (same as gaming for now)
    Default,
}

impl Profile {
    /// Returns (quantum_us, new_flow_bonus_us, starvation_us)
    fn values(&self) -> (u64, u64, u64) {
        match self {
            // Esports: Ultra-aggressive, 1ms quantum for maximum responsiveness
            Profile::Esports => (1000, 4000, 50000),
            // Legacy: High efficiency, 4ms quantum to reduce overhead on older CPUs
            Profile::Legacy => (4000, 12000, 200000),
            // Gaming: Aggressive latency, 2ms quantum
            Profile::Gaming => (2000, 8000, 100000),
            // FIX (explicit delegation): Default explicitly delegates to Gaming rather
            // than duplicating the same literals.  When Gaming values are updated,
            // Default automatically tracks them — no risk of the two diverging silently.
            Profile::Default => Profile::Gaming.values(),
        }
    }

    /// Per-tier starvation thresholds in nanoseconds (4 tiers + padding)
    fn starvation_threshold(&self) -> [u64; 8] {
        match self {
            Profile::Esports => [
                1_500_000,  // T0 Critical: 1.5ms
                4_000_000,  // T1 Interactive: 4ms
                20_000_000, // T2 Frame: 20ms
                50_000_000, // T3 Bulk: 50ms
                50_000_000, 50_000_000, 50_000_000, 50_000_000, // Padding
            ],
            Profile::Legacy => [
                6_000_000,   // T0 Critical: 6ms
                16_000_000,  // T1 Interactive: 16ms
                80_000_000,  // T2 Frame: 80ms
                200_000_000, // T3 Bulk: 200ms
                200_000_000,
                200_000_000,
                200_000_000,
                200_000_000, // Padding
            ],
            // FIX (explicit delegation): Default delegates to Gaming so values
            // stay in sync without duplication.
            Profile::Gaming | Profile::Default => [
                3_000_000,   // T0 Critical: 3ms
                8_000_000,   // T1 Interactive: 8ms
                40_000_000,  // T2 Frame: 40ms
                100_000_000, // T3 Bulk: 100ms
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000, // Padding
            ],
        }
    }

    /// Tier quantum multipliers (fixed-point, 1024 = 1.0x) — 4 tiers + padding
    fn tier_multiplier(&self) -> [u32; 8] {
        match self {
            Profile::Esports => [
                256,  // T0 Critical: 0.25x = 0.25ms — fastest core release
                1024, // T1 Interactive: 1.0x = 1ms
                2048, // T2 Frame: 2.0x = 2ms
                4095, // T3 Bulk: ~4x = 4ms
                4095, 4095, 4095, 4095,
            ],
            // FIX (explicit delegation): Default delegates to Gaming.
            Profile::Gaming | Profile::Default => [
                512,  // T0 Critical: 0.5x = 1ms — releases cores to game threads quickly
                1024, // T1 Interactive: 1.0x = 2ms
                2048, // T2 Frame: 2.0x = 4ms
                4095, // T3 Bulk: ~4x = 8ms
                4095, 4095, 4095, 4095,
            ],
            Profile::Legacy => [
                768,  // T0 Critical: 0.75x — older HW tolerates longer quanta
                1024, // T1 Interactive: 1.0x
                1536, // T2 Frame: 1.5x
                2048, // T3 Bulk: 2.0x — conservative for low-power CPUs
                2048, 2048, 2048, 2048,
            ],
        }
    }

    /// Wait budget per tier in nanoseconds — 4 tiers + padding
    fn wait_budget(&self) -> [u64; 8] {
        match self {
            Profile::Esports => [
                50_000,    // T0 Critical: 50µs
                1_000_000, // T1 Interactive: 1ms
                4_000_000, // T2 Frame: 4ms
                0,         // T3 Bulk: no limit
                0, 0, 0, 0, // Padding
            ],
            Profile::Legacy => [
                200_000,    // T0 Critical: 200µs
                4_000_000,  // T1 Interactive: 4ms
                16_000_000, // T2 Frame: 16ms
                0,          // T3 Bulk: no limit
                0, 0, 0, 0, // Padding
            ],
            // FIX (explicit delegation): Default delegates to Gaming.
            Profile::Gaming | Profile::Default => [
                100_000,   // T0 Critical: 100µs
                2_000_000, // T1 Interactive: 2ms
                8_000_000, // T2 Frame: 8ms
                0,         // T3 Bulk: no limit
                0, 0, 0, 0, // Padding
            ],
        }
    }

    /// Consolidated tier config - packs quantum/multiplier/budget/starvation into 64-bit per tier.
    ///
    /// FIX (#4): `starvation_override` is the CLI `--starvation` value (microseconds).
    /// When provided, all per-tier starvation thresholds are scaled proportionally
    /// relative to the profile's T3 Bulk baseline so the ratio between tiers is preserved.
    fn tier_configs(&self, quantum_us: u64, starvation_override: Option<u64>) -> [u64; 8] {
        let base_starvation = self.starvation_threshold(); // nanoseconds
        let multiplier = self.tier_multiplier();
        let budget = self.wait_budget();

        // Scale per-tier starvation if CLI --starvation overrides the profile default.
        // All tiers scale proportionally: override_ns / default_T3_ns × tier_ns.
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
            // FIX (audit): intf.h PACK_CONFIG takes q_kns in 1024-nanosecond slots
            // (quantum_ns >> 10), NOT microseconds. Storing quantum_us here caused
            // UNPACK_QUANTUM_NS to return quantum_us * 1024 ≈ 2.048ms for a 2000µs
            // quantum instead of the correct 2.000ms (off by ~2.4%).
            let quantum_kns = (quantum_us * 1000) >> 10;
            configs[i] = (multiplier[i] as u64 & 0xFFF)
                | ((quantum_kns & 0xFFFF) << 12)
                | (((budget[i] >> 10) & 0xFFFF) << 28)
                | (((starvation[i] >> 10) & 0xFFFFF) << 44);
        }
        configs
    }
}

/// 🍰 scx_cider: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
/// for CPU scheduling, providing low-latency scheduling for gaming and
/// interactive workloads while maintaining fairness.
///
/// PROFILES set all tuning parameters at once. Individual options override profile defaults.
///
/// 4-TIER SYSTEM (classified by avg_runtime):
///   T0 Critical  (<100µs): IRQ, input, audio, network
///   T1 Interact  (<2ms):   compositor, physics, AI
///   T2 Frame     (<8ms):   game render, encoding
///   T3 Bulk      (≥8ms):   compilation, background
///
/// EXAMPLES:
///   scx_cider                          # Run with gaming profile (default)
///   scx_cider -p esports               # Ultra-low-latency for competitive play
///   scx_cider --quantum 1500           # Gaming profile with custom quantum
///   scx_cider -v                       # Run with live TUI stats display
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "🍰 A sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling",
    verbatim_doc_comment
)]
struct Args {
    /// Scheduler profile preset.
    ///
    /// Profiles configure all tier thresholds, quantum multipliers, and wait budgets.
    /// Individual CLI options (--quantum, etc.) override profile values.
    ///
    /// ESPORTS: Ultra-low-latency for competitive gaming.
    ///   - Quantum: 1000µs, Starvation: 50ms
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs, Starvation: 200ms
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 2000µs, Starvation: 100ms
    ///
    /// DEFAULT: Balanced profile for general desktop use.
    ///   - Currently same as gaming; will diverge in future versions
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 2000].
    ///
    /// How long a task runs before potentially yielding.
    ///
    /// Smaller quantum = more responsive but higher overhead.
    /// Esports: 1000µs | Gaming: 2000µs | Legacy: 4000µs
    /// Recommended range: 1000-8000µs
    #[arg(long, verbatim_doc_comment)]
    quantum: Option<u64>,

    /// Bonus time for newly woken tasks in MICROSECONDS [default: 8000].
    ///
    /// Tasks waking from sleep get this extra time added to their deficit,
    /// allowing them to run longer on first dispatch. Helps bursty workloads.
    ///
    /// Esports: 4000µs | Gaming: 8000µs
    /// Recommended range: 4000-16000µs
    #[arg(long, verbatim_doc_comment)]
    new_flow_bonus: Option<u64>,

    /// Max run time before forced preemption in MICROSECONDS [default: 100000].
    ///
    /// Safety limit: tasks running longer than this are forcibly preempted.
    /// Prevents any single task from monopolizing the CPU.
    /// All per-tier starvation thresholds scale proportionally from this value.
    ///
    /// Esports: 50000µs (50ms) | Gaming: 100000µs (100ms) | Legacy: 200000µs (200ms)
    /// Recommended range: 50000-200000µs
    #[arg(long, verbatim_doc_comment)]
    starvation: Option<u64>,

    /// Enable live TUI (Terminal User Interface) with real-time statistics.
    ///
    /// Shows dispatch counts per tier, tier transitions,
    /// wait time stats, and system topology information.
    /// Press 'q' to exit TUI mode.
    #[arg(long, short, verbatim_doc_comment)]
    verbose: bool,

    /// Statistics refresh interval in SECONDS (only with --verbose).
    ///
    /// How often the TUI updates. Lower values = more responsive but
    /// higher overhead. Has no effect without --verbose.
    ///
    /// Default: 1 second
    #[arg(long, default_value_t = 1, verbatim_doc_comment)]
    interval: u64,
}

impl Args {
    /// Get effective values (profile defaults with CLI overrides applied)
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
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        // Open and load the BPF skeleton
        let skel_builder = BpfSkelBuilder::default();

        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Populate SCX enum RODATA from kernel BTF (SCX_DSQ_LOCAL_ON, SCX_KICK_PREEMPT, etc.)
        scx_utils::import_enums!(open_skel);

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Get effective values (profile + CLI overrides)
        let (quantum, new_flow_bonus, _) = args.effective_values();

        // ETD: Empirical Topology Discovery — run in background so the scheduler
        // loads immediately. Data is only used for the TUI heatmap; the scheduler
        // operates correctly without it. The TUI will show "Calibrating..." until
        // the background thread signals completion by populating the matrix.
        info!("Starting ETD calibration in background...");
        let nr_cpus_cal = topo.nr_cpus;
        let latency_matrix = Arc::new(Mutex::new(
            vec![vec![0.0f64; nr_cpus_cal]; nr_cpus_cal],
        ));
        let matrix_bg = latency_matrix.clone();

        // FIX (#7): Suppress ETD stdout output when TUI/verbose mode is active.
        // The TUI uses crossterm raw mode + alternate screen; concurrent stdout
        // writes from the ETD thread corrupt the display. In verbose mode, the
        // calibration is silent — progress is visible indirectly when the heatmap
        // populates in the startup screen.
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
            // FIX (#5): Handle poisoned mutex gracefully instead of panicking.
            // A panic in the ETD thread poisons the mutex — recover the inner
            // value rather than crashing the scheduler process.
            match matrix_bg.lock() {
                Ok(mut m) => *m = result,
                Err(e) => *e.into_inner() = result,
            }
        });

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            rodata.enable_stats = args.verbose;

            // FIX (#4): Pass CLI --starvation override so per-tier thresholds are
            // actually applied to BPF rodata. Previously _starvation was computed
            // and then discarded; now tier_configs() scales all tier thresholds
            // proportionally when the CLI arg is present.
            rodata.tier_configs = args.profile.tier_configs(quantum, args.starvation);

            // Topology: only has_hybrid is live (DVFS scaling in cider_tick)
            rodata.has_hybrid = topo.has_hybrid_cores;

            // Per-LLC DSQ partitioning: populate CPU→LLC mapping
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(64) as u32; // Rule 39: bounds kick scan loop
            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
        }

        // Load the BPF program
        let skel = open_skel.load().context("Failed to load BPF program")?;

        Ok(Self {
            skel,
            args,
            topology: topo,
            latency_matrix,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        // Attach the scheduler
        let _link = self
            .skel
            .maps
            .cider_ops
            .attach_struct_ops()
            .context("Failed to attach scheduler")?;

        self.show_startup_splash()?;

        if self.args.verbose {
            // Run TUI mode
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
            )?;
        } else {
            // FIX (#1): signalfd is the sole signal handler. The ctrlc crate
            // previously installed a competing sigaction handler that raced with
            // this signalfd, causing one mechanism to silently eat signals meant
            // for the other. Using only signalfd here is correct.

            // Block SIGINT and SIGTERM from normal delivery
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGINT);
            mask.add(Signal::SIGTERM);
            mask.thread_block().context("Failed to block signals")?;

            // Create signalfd to receive signals as readable events
            let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)
                .context("Failed to create signalfd")?;

            use nix::poll::{poll, PollFd, PollFlags};
            use std::os::fd::BorrowedFd;

            loop {
                // Block for up to 60 seconds, then check UEI
                // poll() returns: >0 = readable, 0 = timeout, -1 = error
                // SAFETY: sfd is valid for the duration of this loop
                let poll_fd = unsafe {
                    PollFd::new(BorrowedFd::borrow_raw(sfd.as_raw_fd()), PollFlags::POLLIN)
                };
                let mut fds = [poll_fd];
                let result = poll(&mut fds, nix::poll::PollTimeout::from(60_000u16)); // 60 seconds

                match result {
                    Ok(n) if n > 0 => {
                        // Signal received - read it to clear and exit
                        if let Ok(Some(siginfo)) = sfd.read_signal() {
                            info!("Received signal {} - shutting down", siginfo.ssi_signo);
                            shutdown.store(true, Ordering::Relaxed);
                        }
                        break;
                    }
                    Ok(_) => {
                        // Timeout - check UEI
                        if scx_utils::uei_exited!(&self.skel, uei) {
                            match scx_utils::uei_report!(&self.skel, uei) {
                                Ok(reason) => {
                                    warn!("BPF scheduler exited: {:?}", reason);
                                }
                                Err(e) => {
                                    warn!("BPF scheduler exited (failed to get reason: {})", e);
                                }
                            }
                            break;
                        }
                    }
                    Err(nix::errno::Errno::EINTR) => {
                        // Interrupted - check shutdown flag
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("poll() error: {}", e);
                        break;
                    }
                }
            }
        }

        info!("scx_cider scheduler shutting down");
        Ok(())
    }

    fn show_startup_splash(&self) -> Result<()> {
        let (q, _nfb, starv) = self.args.effective_values();
        let profile_str = format!("{:?}", self.args.profile).to_uppercase();

        // FIX (#5): Recover from a poisoned mutex rather than panicking.
        // If the ETD thread panicked, the mutex is poisoned — extract the inner
        // value (which may be a partial matrix) rather than crashing.
        //
        // FIX (audit): Clone the matrix immediately to release the MutexGuard
        // before entering render_startup_screen's 4,200ms animation loop.
        // Previously the guard was held for the full animation duration, blocking
        // the ETD background thread from writing its result — the startup heatmap
        // always showed "Calibrating..." even when ETD finished first.
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

    // FIX (#1): Use only signalfd for signal handling (in run() below).
    // The ctrlc::set_handler call was removed — it installed a competing sigaction
    // handler for SIGINT/SIGTERM that raced with the signalfd in the event loop,
    // causing one mechanism to silently eat signals meant for the other.
    let shutdown = Arc::new(AtomicBool::new(false));

    // Create open object for BPF - needs to outlive scheduler
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Create and run the scheduler
    let mut scheduler = Scheduler::new(args, &mut open_object)?;
    scheduler.run(shutdown)?;

    Ok(())
}
