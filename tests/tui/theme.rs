use std::time::Instant;
use vulnclaw_tui::theme::*;

#[test]
fn spinner_animates_off_the_wall_clock() {
    let first = spinner_frame_at(true, 0);
    let second = spinner_frame_at(true, 90);
    assert!("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".contains(first));
    assert!("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".contains(second));
    assert_ne!(first, second, "spinner must advance with its clock");
    assert_eq!(spinner_frame_at(false, 90), ' ');
}

#[test]
fn equalizer_returns_a_fixed_row_of_bars() {
    let eq = equalizer_frame_at(1_000);
    assert_eq!(eq.chars().count(), 6);
    assert!(eq.chars().all(|character| "▁▂▃▄▅▆▇█".contains(character)));
}

#[test]
fn elapsed_label_formats_mm_ss_and_is_empty_when_idle() {
    assert_eq!(elapsed_label(None), "");
    let label = elapsed_label(Some(Instant::now()));
    assert!(label.starts_with("⏱ "));
    assert!(label.ends_with("00:00") || label.contains(':'));
}

#[test]
fn pulse_border_rests_when_idle_and_breathes_when_active() {
    assert_eq!(pulse_border_at(false, 0), BORDER);
    assert_eq!(pulse_border_at(true, 0), ACTION);
    assert_eq!(pulse_border_at(true, 800), SEAFOAM);
}

#[test]
fn blink_phase_toggles_over_time() {
    assert!(blink_on_at(0));
    assert!(!blink_on_at(450));
    assert!(blink_on_at(900));
}
