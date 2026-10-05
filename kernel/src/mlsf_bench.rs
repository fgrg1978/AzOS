// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Opt-in measurement of the kernel's floating-point work (feature
//! `mlsf-bench`, off in every default, board and gate build).
//!
//! Times the f32 paths the kernel ran on a normal boot until they moved to
//! the ring-3 ML service (wave 9) or were removed (wave 10) — the MLP the
//! behavior loop and the ml-demo task called, the camera feature extractor
//! the behavior loop called every cycle, and the GGUF MLP Phase C ran when
//! `/fat/POLICY.GGF` existed — in a tight loop, early in `kernel_main` (hart 0
//! only, timer interrupt still off), then halts. Meant to be booted under
//! QEMU `-icount shift=0`, where one instruction is one nanosecond of virtual
//! time, so `ns` below is an instruction count.
//!
//! Each lane runs twice, `ITERS` and `2 * ITERS` calls: the second total must
//! be twice the first (minus the loop floor), which is what shows the loop
//! body was not folded away. Inputs and outputs go through `black_box` for
//! the same reason; the checksum is the wrapping sum of the result bit patterns.
//!
//! The GGUF lane needs `build/policy.gguf` (`python3 tools/make_gguf.py`).

use core::hint::black_box;
use azos_drv_sys::kprintln;

const ITERS: u64 = 1000;

/// The file `make` copies to `/fat/POLICY.GGF` on the riscv64 disks.
static POLICY_GGUF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../build/policy.gguf"));

#[inline(always)]
fn ticks() -> u64 {
    let t: u64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("isb", "mrs {0}, cntvct_el0", out(reg) t, options(nostack));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("rdtime {0}", out(reg) t, options(nostack));
    }
    t
}

fn freq() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let f: u64;
        unsafe { core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) f, options(nomem, nostack)); }
        f
    }
    #[cfg(target_arch = "riscv64")]
    {
        azos_drv_sys::timebase::TIMER_FREQ
    }
}

fn lane<F: FnMut(u64) -> u32>(name: &str, mut body: F) {
    let f = freq();
    for n in [ITERS, 2 * ITERS] {
        let mut chk = 0u32;
        let t0 = ticks();
        for i in 0..n {
            chk = chk.wrapping_add(body(black_box(i)));
        }
        let t1 = ticks();
        let chk = black_box(chk);
        let d = t1.wrapping_sub(t0);
        let ns = ((d as u128) * 1_000_000_000u128 / (f as u128)) as u64;
        kprintln!("[MLSF] {} iters={} ticks={} freq={} ns={} ns_per_call_x100={} chk={:#010x}",
                  name, n, d, f, ns, ns * 100 / n, chk);
    }
}

fn bits3(v: &[f32]) -> u32 {
    v.iter().fold(0u32, |a, x| a ^ x.to_bits())
}

pub fn run() {
    kprintln!("[MLSF] ── start (arch={}, iters={}/{}) ──",
              if cfg!(target_arch = "aarch64") { "aarch64" } else { "riscv64" },
              ITERS, 2 * ITERS);

    lane("floor", |i| black_box(i as u32));

    // The former ml-demo task and behavior loop: azos_ml::mlp_infer + argmax3.
    lane("mlp_infer", |_| {
        let inp = black_box(azos_ml::DEMO_INPUT);
        let l = azos_ml::mlp_infer(&inp);
        bits3(&l) ^ azos_ml::argmax3(&l) as u32
    });

    // Behavior loop, every cycle: cam_capture + cam_extract_features.
    lane("cam_features", |i| {
        let f = azos_camera::cam_capture(black_box((i % 3) as u8));
        let c = azos_camera::cam_extract_features(&f);
        c.dist_front.to_bits() ^ c.dist_right.to_bits()
    });

    // One behavior cycle's whole ML section (kernel/src/tasks/behavior.rs behavior_task:
    // capture, extract, u32 -> f32 input, mlp_infer, argmax3).
    lane("behavior_ml_step", |i| {
        let f = azos_camera::cam_capture(black_box((i % 3) as u8));
        let c = black_box(azos_camera::cam_extract_features(&f));
        let (front, right) = black_box((600u32 + (i % 7) as u32, 300u32));
        let input: [f32; 4] = [front as f32 / 1000.0, right as f32 / 1000.0, 0.5, 0.9];
        let l = azos_ml::mlp_infer(&input);
        c.dist_front.to_bits() ^ bits3(&l) ^ azos_ml::argmax3(&l) as u32
    });

    // Phase C (boot, when /fat/POLICY.GGF exists): gguf_mlp_infer + argmax.
    match azos_ml::gguf::GgufFile::parse(POLICY_GGUF) {
        Some(g) => lane("gguf_mlp_infer", |_| {
            let inp = black_box([0.8f32, 0.3, 0.5, 0.9]);
            let mut l = [0.0f32; 3];
            let ok = azos_ml::ggml_nano::gguf_mlp_infer(&g, &inp, &mut l);
            bits3(&l) ^ azos_ml::ggml_nano::argmax(&l) as u32 ^ ok as u32
        }),
        None => kprintln!("[MLSF] gguf_mlp_infer PARSE-FAILED"),
    }

    kprintln!("[MLSF] ── done ──");
}
