// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CPUID energy source (x86 hybrid parts): the decode of each logical
//! processor's core type on synthetic CPUID words
//! (`arch/x86_64/src/ext/hybrid.rs`), the model the classes make
//! (`EnergyModel::from_core_classes`), where it ranks among the sources
//! (`resolve`) and what EAS does with it.
//!
//! Every gate has a test that flips only that gate. Canaries (by hand, each
//! must turn the named tests red):
//! * `decode`, Intel: drop the `CPUID.(7,0):EDX[15]` test:
//!   `a_cpu_that_is_not_hybrid_reports_no_type_whatever_leaf_1a_holds`;
//!   swap the 0x20/0x40 arms: `intel_types_are_read_from_leaf_1a`;
//! * `decode`, AMD: drop the `0x80000026:EAX[30]` test:
//!   `a_cpu_that_is_not_hybrid_reports_no_type_whatever_leaf_1a_holds`; read
//!   `EBX[27:24]` instead of `[31:28]`: `amd_types_are_read_from_leaf_80000026`;
//! * `from_core_classes`: treat `Unknown` as `Efficiency`:
//!   `a_cpu_of_unknown_type_refuses_the_model`; drop the mixed-`Uniform` test:
//!   `a_cpu_that_reports_no_type_among_typed_ones_refuses_the_model`;
//!   build one domain from both classes: `one_domain_per_class`;
//! * `from_core_reports`: treat a silent CPU as `Uniform`:
//!   `a_cpu_that_recorded_nothing_refuses_the_model_and_is_named` and
//!   `a_symmetric_machine_with_a_silent_cpu_is_refused_too_not_taken_as_symmetric`;
//!   drop a bit from `missing`: the first of them;
//! * `resolve`: put the CPUID source before the DTB:
//!   `the_cpuid_model_is_the_last_source`; let a refused DTB model fall
//!   through: `a_dtb_model_that_was_refused_is_not_replaced_by_cpuid`.

use azos_energy::model::{
    CoreClass, CoreReports, EasChoice, CAPACITY_SCALE, CPUID_EFFICIENCY_CAPACITY, CPUID_EFFICIENCY_POWER_MW,
    CPUID_PERFORMANCE_POWER_MW, MAX_MODEL_CPUS,
};
use azos_energy::{resolve, EnergyModel, ModelFault, ModelSource, PerfDomain};

use crate::cpu::features::Vendor;
use crate::ext::hybrid::{decode, recorded, record, CoreKind, HybridLeaves, MAX_RECORDED};

/// An Alder Lake logical processor: CPUID.(7,0):EDX bit 15, leaf 0x1A type.
fn intel(l7_edx_hybrid: bool, core_type: u32) -> HybridLeaves {
    HybridLeaves {
        vendor: Vendor::Intel,
        l7_edx: if l7_edx_hybrid { 1 << 15 | 1 << 14 } else { 1 << 14 },
        l1a_eax: core_type << 24 | 1, // native model id 1
        ..HybridLeaves::default()
    }
}

/// A Zen 5 / Zen 5c logical processor: CPUID.0x80000026.
fn amd(hetero: bool, core_type: u32) -> HybridLeaves {
    HybridLeaves {
        vendor: Vendor::Amd,
        e26_eax: if hetero { 1 << 30 | 0x4 } else { 0x4 },
        e26_ebx: core_type << 28 | 0x2 << 24 | 0x10, // native model id 2, 16 logical processors
        ..HybridLeaves::default()
    }
}

#[test]
fn intel_types_are_read_from_leaf_1a() {
    assert_eq!(decode(&intel(true, 0x40)), CoreKind::Performance);
    assert_eq!(decode(&intel(true, 0x20)), CoreKind::Efficiency);
    for other in [0x00, 0x10, 0x30, 0x41, 0x60, 0xff] {
        assert_eq!(decode(&intel(true, other)), CoreKind::Unrecognised, "type {other:#x}");
    }
}

#[test]
fn amd_types_are_read_from_leaf_80000026() {
    assert_eq!(decode(&amd(true, 0)), CoreKind::Performance);
    assert_eq!(decode(&amd(true, 1)), CoreKind::Efficiency);
    for other in [2, 3, 8, 15] {
        assert_eq!(decode(&amd(true, other)), CoreKind::Unrecognised, "type {other}");
    }
}

#[test]
fn a_cpu_that_is_not_hybrid_reports_no_type_whatever_leaf_1a_holds() {
    // Leaf 0x1A is only meaningful on a part that says it is hybrid: an
    // older part returns the highest basic leaf's data for it.
    assert_eq!(decode(&intel(false, 0x40)), CoreKind::Uniform);
    assert_eq!(decode(&intel(false, 0x20)), CoreKind::Uniform);
    assert_eq!(decode(&amd(false, 0)), CoreKind::Uniform);
    assert_eq!(decode(&amd(false, 1)), CoreKind::Uniform);
}

#[test]
fn another_vendors_words_mean_nothing() {
    // Intel's words under an AMD vendor string, and the other way round.
    let mut l = intel(true, 0x20);
    l.vendor = Vendor::Amd;
    assert_eq!(decode(&l), CoreKind::Uniform);
    let mut l = amd(true, 1);
    l.vendor = Vendor::Intel;
    assert_eq!(decode(&l), CoreKind::Uniform);
    for v in [Vendor::Unknown, Vendor::Hygon] {
        let mut l = intel(true, 0x20);
        l.vendor = v;
        assert_eq!(decode(&l), CoreKind::Uniform, "{v:?}");
    }
    // A host build reads nothing, and a part that reports nothing is uniform.
    assert_eq!(decode(&HybridLeaves::default()), CoreKind::Uniform);
}

#[test]
fn a_cpu_records_its_own_kind() {
    // Slots 28..31 belong to this test; every other test uses none.
    assert_eq!(recorded(28), None);
    record(28, CoreKind::Efficiency);
    record(29, CoreKind::Performance);
    record(30, CoreKind::Uniform);
    record(31, CoreKind::Unrecognised);
    assert_eq!(
        [28, 29, 30, 31].map(recorded),
        [Some(CoreKind::Efficiency), Some(CoreKind::Performance), Some(CoreKind::Uniform), Some(CoreKind::Unrecognised)]
    );
    // Past the table: not recorded, not an error.
    record(MAX_RECORDED, CoreKind::Performance);
    assert_eq!(recorded(MAX_RECORDED), None);
    assert_eq!(MAX_RECORDED, MAX_MODEL_CPUS);
}

// ── The model ───────────────────────────────────────────────────────────────

/// A 12900K: CPUs 0..16 are the eight P-cores' threads, 16..24 the E-cores.
fn alder_lake() -> Vec<CoreClass> {
    (0..24).map(|c| if c < 16 { CoreClass::Performance } else { CoreClass::Efficiency }).collect()
}

const REF_KHZ: u32 = 3_187_200;

fn model(classes: &[CoreClass]) -> EnergyModel {
    EnergyModel::from_core_classes(classes, REF_KHZ).unwrap().unwrap()
}

#[test]
fn one_domain_per_class() {
    let m = model(&alder_lake());
    assert_eq!(m.source, ModelSource::Cpuid);
    assert_eq!(m.domains().len(), 2);
    let (p, e) = (&m.domains()[0], &m.domains()[1]);
    assert_eq!((p.cpus, e.cpus), (0x0000_ffff, 0x00ff_0000));
    for d in m.domains() {
        assert_eq!(d.opps().len(), 1);
        assert_eq!(d.opps()[0].freq_khz, REF_KHZ);
    }
    assert_eq!((p.max_capacity(), p.opps()[0].power_mw), (CAPACITY_SCALE, CPUID_PERFORMANCE_POWER_MW));
    assert_eq!((e.max_capacity(), e.opps()[0].power_mw), (CPUID_EFFICIENCY_CAPACITY, CPUID_EFFICIENCY_POWER_MW));
    assert_eq!(m.validate(24), Ok(()), "the model is valid for the machine it was made from");
    assert!(m.is_asymmetric());
    assert_eq!(m.domain_of(3).map(|d| d.max_capacity()), Some(CAPACITY_SCALE));
    assert_eq!(m.domain_of(20).map(|d| d.max_capacity()), Some(CPUID_EFFICIENCY_CAPACITY));
}

#[test]
fn cpus_may_interleave_the_classes() {
    // AMD numbers its CPUs as the firmware lists them: Zen 5c can be anywhere.
    let c: Vec<_> = (0..8).map(|i| if i % 4 == 3 { CoreClass::Efficiency } else { CoreClass::Performance }).collect();
    let m = model(&c);
    assert_eq!((m.domains()[0].cpus, m.domains()[1].cpus), (0b0111_0111, 0b1000_1000));
    assert_eq!(m.validate(8), Ok(()));
}

#[test]
fn a_machine_with_one_class_or_none_has_nothing_for_cpuid_to_add() {
    let none = |c: &[CoreClass]| EnergyModel::from_core_classes(c, REF_KHZ);
    assert_eq!(none(&[CoreClass::Uniform; 8]), Ok(None), "no CPU reports a type");
    assert_eq!(none(&[CoreClass::Performance; 8]), Ok(None), "all performance");
    assert_eq!(none(&[CoreClass::Efficiency; 4]), Ok(None), "all efficiency");
    assert_eq!(none(&[]), Ok(None));
}

#[test]
fn a_cpu_of_unknown_type_refuses_the_model() {
    let mut c = alder_lake();
    c[5] = CoreClass::Unknown;
    assert_eq!(
        EnergyModel::from_core_classes(&c, REF_KHZ),
        Err(ModelFault::CoreClassUnknown { cpu: 5 }),
        "an unrecognised type or a CPU that never came up is not guessed"
    );
    // The first one is named.
    c[2] = CoreClass::Unknown;
    assert_eq!(EnergyModel::from_core_classes(&c, REF_KHZ), Err(ModelFault::CoreClassUnknown { cpu: 2 }));
    // Even when every other CPU is of one class.
    let mut c = [CoreClass::Performance; 4];
    c[3] = CoreClass::Unknown;
    assert_eq!(EnergyModel::from_core_classes(&c, REF_KHZ), Err(ModelFault::CoreClassUnknown { cpu: 3 }));
    // Unknown alone (nothing typed) is still unknown, not "uniform".
    assert_eq!(
        EnergyModel::from_core_classes(&[CoreClass::Uniform, CoreClass::Unknown], REF_KHZ),
        Err(ModelFault::CoreClassUnknown { cpu: 1 })
    );
}

#[test]
fn a_cpu_that_reports_no_type_among_typed_ones_refuses_the_model() {
    let mut c = alder_lake();
    c[7] = CoreClass::Uniform;
    assert_eq!(EnergyModel::from_core_classes(&c, REF_KHZ), Err(ModelFault::CoreClassUnknown { cpu: 7 }));
}

/// The deferred install's read of the records: `reports(n, f)` is what the
/// boot CPU gets from the CPUs that recorded (`f(cpu)`).
fn reports(n: usize, f: impl Fn(usize) -> Option<CoreClass>) -> CoreReports {
    EnergyModel::from_core_reports(n, REF_KHZ, f)
}

#[test]
fn reports_of_every_cpu_make_the_model_the_classes_make() {
    let c = alder_lake();
    let r = reports(c.len(), |i| Some(c[i]));
    assert_eq!(r.missing, 0);
    assert_eq!(r.model, EnergyModel::from_core_classes(&c, REF_KHZ).transpose());
    assert!(matches!(r.model, Some(Ok(_))));
}

#[test]
fn a_cpu_that_recorded_nothing_refuses_the_model_and_is_named() {
    // CPU 5 started but never recorded (the install waited 2 s for it).
    let c = alder_lake();
    let r = reports(c.len(), |i| (i != 5).then_some(c[i]));
    assert_eq!(r.missing, 1 << 5);
    assert_eq!(r.model, Some(Err(ModelFault::CoreClassUnknown { cpu: 5 })));
    // Several missing: the mask names every one, the fault the first.
    let r = reports(c.len(), |i| (i % 8 != 3).then_some(c[i]));
    assert_eq!(r.missing, 1 << 3 | 1 << 11 | 1 << 19);
    assert_eq!(r.model, Some(Err(ModelFault::CoreClassUnknown { cpu: 3 })));
}

#[test]
fn a_symmetric_machine_with_a_silent_cpu_is_refused_too_not_taken_as_symmetric() {
    // Missing is not Uniform: a CPU that may be the odd one out is not assumed
    // to match the rest.
    let r = reports(4, |i| (i != 2).then_some(CoreClass::Uniform));
    assert_eq!(r.missing, 1 << 2);
    assert_eq!(r.model, Some(Err(ModelFault::CoreClassUnknown { cpu: 2 })));
}

#[test]
fn a_machine_whose_cpus_all_report_the_same_has_no_cpuid_model() {
    let r = reports(8, |_| Some(CoreClass::Uniform));
    assert_eq!((r.missing, r.model), (0, None));
    let r = reports(8, |_| Some(CoreClass::Performance));
    assert_eq!((r.missing, r.model), (0, None));
}

#[test]
fn the_model_covers_the_cpus_that_started_and_validates_for_exactly_them() {
    // 8 CPUs wanted, 6 started (the prefix the scheduler uses): the deferred
    // install models 0..6 and validates against 6, not against 8.
    let c: Vec<_> = (0..6).map(|i| if i < 4 { CoreClass::Performance } else { CoreClass::Efficiency }).collect();
    let r = reports(6, |i| Some(c[i]));
    assert_eq!(r.missing, 0);
    let Some(Ok(m)) = r.model else { panic!("{:?}", r.model) };
    assert_eq!(m.domains().iter().fold(0u32, |a, d| a | d.cpus), 0b11_1111);
    assert_eq!(m.validate(6), Ok(()));
    assert!(m.validate(8).is_err());
}

#[test]
fn cpus_past_what_a_model_can_name_are_left_out() {
    let c: Vec<_> = (0..48).map(|i| if i < 24 { CoreClass::Performance } else { CoreClass::Efficiency }).collect();
    let m = model(&c[..40]);
    assert_eq!((m.domains()[0].cpus, m.domains()[1].cpus), (0x00ff_ffff, 0xff00_0000));
    // Validated against the 32 CPUs it can name, as `validate` clamps.
    assert_eq!(m.validate(48), Ok(()));
    // A type past the 32nd that nothing could name is not judged.
    let mut c = c;
    c[40] = CoreClass::Unknown;
    assert!(EnergyModel::from_core_classes(&c, REF_KHZ).is_ok());
}

#[test]
fn no_clock_reading_is_a_model_the_validation_refuses() {
    // The TSC rate unread: the OPP has no frequency, and `resolve` refuses it.
    let m = EnergyModel::from_core_classes(&alder_lake(), 0).unwrap().unwrap();
    assert_eq!(m.validate(24), Err(ModelFault::ZeroFrequency { domain: 0, opp: 0 }));
}

// ── Where it ranks ──────────────────────────────────────────────────────────

/// A model whose one domain names no CPU: `validate` refuses it.
fn no_cpus(source: ModelSource) -> EnergyModel {
    let mut m = EnergyModel::from_source(source);
    m.push_domain(PerfDomain::new(0)).unwrap();
    m
}

fn cpuid() -> Option<Result<EnergyModel, ModelFault>> {
    Some(Ok(model(&alder_lake())))
}

#[test]
fn the_cpuid_model_is_the_last_source() {
    let (m, r) = resolve(&EnergyModel::NONE, None, cpuid(), None, 24);
    assert_eq!((m.source, r.source), (ModelSource::Cpuid, ModelSource::Cpuid));
    assert_eq!((r.topology_fault, r.dtb_fault, r.cpuid_fault), (None, None, None));
    assert_eq!(m.domains().len(), 2);

    // A topology model wins, and so does a DTB's.
    let topo = crate::model::valid();
    let (m, r) = resolve(&topo, None, cpuid(), None, 2);
    assert_eq!((m.source, r.source), (ModelSource::Topology, ModelSource::Topology));
    let mut dtb = crate::model::valid();
    dtb.source = ModelSource::Dtb;
    let (m, r) = resolve(&EnergyModel::NONE, Some(Ok(dtb)), cpuid(), None, 2);
    assert_eq!((m.source, r.source), (ModelSource::Dtb, ModelSource::Dtb));

    // Nothing to resolve: none.
    let (m, r) = resolve(&EnergyModel::NONE, None, None, None, 24);
    assert_eq!((m, r.source, r.cpuid_fault), (EnergyModel::NONE, ModelSource::None, None));
}

#[test]
fn a_topology_model_that_was_refused_is_not_replaced_by_cpuid() {
    let bad = no_cpus(ModelSource::Topology);
    let (m, r) = resolve(&bad, None, cpuid(), None, 2);
    assert_eq!(m, EnergyModel::NONE);
    assert_eq!((r.source, r.topology_fault, r.cpuid_fault), (ModelSource::None, Some(ModelFault::EmptyCpuMask { domain: 0 }), None));
}

#[test]
fn a_dtb_model_that_was_refused_is_not_replaced_by_cpuid() {
    let bad = no_cpus(ModelSource::Dtb);
    let (m, r) = resolve(&EnergyModel::NONE, Some(Ok(bad)), cpuid(), None, 2);
    assert_eq!(m, EnergyModel::NONE);
    assert_eq!((r.source, r.dtb_fault, r.cpuid_fault), (ModelSource::None, Some(ModelFault::EmptyCpuMask { domain: 0 }), None));
    let (m, r) = resolve(&EnergyModel::NONE, Some(Err(ModelFault::DtPartialTables)), cpuid(), None, 24);
    assert_eq!((m, r.dtb_fault, r.cpuid_fault), (EnergyModel::NONE, Some(ModelFault::DtPartialTables), None));
}

#[test]
fn a_cpuid_model_that_fails_is_refused_with_its_own_fault() {
    // Built for 24 CPUs, the machine has 8: it names CPUs that are not there.
    let (m, r) = resolve(&EnergyModel::NONE, None, cpuid(), None, 8);
    assert_eq!(m, EnergyModel::NONE);
    assert_eq!((r.source, r.cpuid_fault), (ModelSource::None, Some(ModelFault::CpuAbsent { domain: 0, cpu: 8 })));
    // One that could not be built carries the builder's fault.
    let f = ModelFault::CoreClassUnknown { cpu: 3 };
    let (m, r) = resolve(&EnergyModel::NONE, None, Some(Err(f)), None, 24);
    assert_eq!((m, r.cpuid_fault, r.topology_fault, r.dtb_fault), (EnergyModel::NONE, Some(f), None, None));
}

// ── What EAS does with it ───────────────────────────────────────────────────

fn eas(m: &EnergyModel, task: u32, prev: usize) -> EasChoice {
    m.eas_pick(&[0; 24], task, prev, 0x00ff_ffff)
}

#[test]
fn a_small_task_goes_to_an_efficiency_core_and_a_big_one_to_a_performance_core() {
    let m = model(&alder_lake());
    // From a performance core: the efficiency core does it for half the energy.
    assert!(matches!(eas(&m, 100, 0), EasChoice::Cpu(c) if c >= 16), "{:?}", eas(&m, 100, 0));
    // From an efficiency core it stays.
    assert!(matches!(eas(&m, 100, 20), EasChoice::Cpu(c) if c >= 16));
    // 500 is more than an efficiency core can hold (80% of 600 = 480).
    assert!(matches!(eas(&m, 500, 20), EasChoice::Cpu(c) if c < 16), "{:?}", eas(&m, 500, 20));
    // A task that fits no core hands placement back.
    assert_eq!(eas(&m, 900, 0), EasChoice::Overutilised);
}

#[test]
fn the_efficiency_class_is_cheaper_per_unit_of_work_than_the_performance_class() {
    // The one ratio EAS reads from the relative power: power / capacity.
    let (p, e) = (CPUID_PERFORMANCE_POWER_MW as u64, CPUID_EFFICIENCY_POWER_MW as u64);
    assert!(e * CAPACITY_SCALE as u64 / (CPUID_EFFICIENCY_CAPACITY as u64) < p);
    assert!(CPUID_EFFICIENCY_CAPACITY < CAPACITY_SCALE);
}
