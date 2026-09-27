//! UTC formatting, including timestamps before the Unix epoch.

pub(crate) fn timestamp(time: i64, separator: char) -> String {
    let days = time.div_euclid(86_400_000);
    let of_day = time.rem_euclid(86_400_000);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let of_era = z.rem_euclid(146_097);
    let y = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * y + y / 4 - y / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = y + era * 400 + i64::from(month <= 2);
    let zone = if separator == 'T' { "Z" } else { "" };
    format!(
        "{year:04}-{month:02}-{day:02}{separator}{:02}:{:02}:{:02}.{:03}{zone}",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1_000 % 60,
        of_day % 1_000
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dates_round_trip() {
        for time in [-1, 0, 951_782_400_000, 1_790_244_930_123] {
            let parsed: jiff::Timestamp = timestamp(time, 'T').parse().unwrap();
            assert_eq!(parsed.as_millisecond(), time);
        }
    }
}
