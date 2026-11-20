pub mod baseline;
pub mod config;

/// Returns the current UTC time formatted as an RFC 3339 timestamp
/// (e.g. `2024-01-15T12:34:56Z`), 20 characters long and ending with 'Z'.
pub fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);

    let (year, month, day) = days_to_ymd(days);

    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Converts a number of days since the Unix epoch (1970-01-01) into a
/// `(year, month, day)` tuple in the proleptic Gregorian calendar.
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Shift epoch to 0000-03-01 so leap days fall at the end of the year.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Returns true if the given year is a leap year in the Gregorian calendar.
#[allow(dead_code)]
fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_now_format() {
        let ts = rfc3339_now();
        assert_eq!(ts.len(), 20, "timestamp should be 20 chars: {}", ts);
        assert!(ts.ends_with('Z'), "timestamp should end with 'Z': {}", ts);
        assert_eq!(&ts[4..5], "-", "expected '-' at index 4: {}", ts);
        assert_eq!(&ts[10..11], "T", "expected 'T' at index 10: {}", ts);
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-15 is 19737 days after the Unix epoch.
        assert_eq!(days_to_ymd(19_737), (2024, 1, 15));
    }

    #[test]
    fn test_is_leap() {
        assert!(is_leap(2024));
        assert!(!is_leap(2023));
        assert!(!is_leap(1900));
        assert!(is_leap(2000));
    }
}