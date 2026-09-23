//! Bounded, whole-stream reservoir samples of consecutive hit gaps.
//! Periodicity is a structural observation, never a proof of JVM metadata.
use super::*;

pub const MAX_GROUPS: usize = 4096;
const SAMPLE_GAPS: usize = 256;
const EXAMPLES: usize = 16;
const MIN_GAPS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapExample {
    pub from: u64,
    pub to: u64,
    pub gap: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    pub hits: u64,
    pub detection_votes: u64,
    pub first_offset: u64,
    pub last_offset: u64,
    pub total_gaps: u64,
    pub sampled_gaps: usize,
    pub median_gap: Option<f64>,
    pub mode_gap: Option<u64>,
    pub mode_sample_count: usize,
    pub mode_fraction: Option<f64>,
    pub periodic: bool,
    pub classification: String,
    pub gap_examples: Vec<GapExample>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Wide,
    Narrow,
}
impl Kind {
    fn slot(self) -> usize {
        match self {
            Self::Wide => 0,
            Self::Narrow => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Wide => "wide",
            Self::Narrow => "narrow",
        }
    }
}

#[derive(Default)]
struct Group {
    hits: u64,
    votes: u64,
    first: u64,
    last: u64,
    samples: Vec<(u64, u64)>, // (gap, destination); never gaps between sampled hits
    rng: u64,
}
impl Group {
    fn observe(&mut self, offset: u64, vote: bool) {
        if self.hits == 0 {
            self.first = offset;
        } else {
            let sample = (offset - self.last, offset);
            if self.samples.len() < SAMPLE_GAPS {
                self.samples.push(sample);
            } else {
                // Algorithm R, deterministic SplitMix64 PRNG. Samples cover the
                // entire hit stream, not just an early periodic prefix.
                self.rng = self.rng.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = self.rng;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                let slot = z % self.hits;
                if slot < SAMPLE_GAPS as u64 {
                    self.samples[slot as usize] = sample;
                }
            }
        }
        self.hits += 1;
        self.votes += u64::from(vote);
        self.last = offset;
    }
    fn finish(self) -> GroupStats {
        let mut gaps: Vec<_> = self.samples.iter().map(|&(g, _)| g).collect();
        gaps.sort_unstable();
        let mut frequency = BTreeMap::new();
        for gap in &gaps {
            *frequency.entry(*gap).or_insert(0usize) += 1;
        }
        // Stable tie break: choose the smaller gap.
        let mode = frequency
            .iter()
            .max_by(|(ga, na), (gb, nb)| na.cmp(nb).then(gb.cmp(ga)));
        let mode_count = mode.map_or(0, |(_, n)| *n);
        let median = if gaps.is_empty() {
            None
        } else {
            Some((gaps[(gaps.len() - 1) / 2] as f64 + gaps[gaps.len() / 2] as f64) / 2.0)
        };
        let periodic = gaps.len() >= MIN_GAPS && mode_count * 10 > gaps.len() * 9;
        let mut examples = self.samples;
        examples.sort_unstable_by_key(|&(_, to)| to);
        let examples = (0..examples.len().min(EXAMPLES))
            .map(|i| {
                let (gap, to) = examples[i * examples.len() / examples.len().min(EXAMPLES)];
                GapExample {
                    from: to - gap,
                    to,
                    gap,
                }
            })
            .collect();
        GroupStats {
            hits: self.hits,
            detection_votes: self.votes,
            first_offset: self.first,
            last_offset: self.last,
            total_gaps: self.hits.saturating_sub(1),
            sampled_gaps: gaps.len(),
            median_gap: median,
            mode_gap: mode.map(|(gap, _)| *gap),
            mode_sample_count: mode_count,
            mode_fraction: (!gaps.is_empty()).then(|| mode_count as f64 / gaps.len() as f64),
            periodic,
            classification: if periodic {
                "periodic-structure"
            } else if gaps.len() < MIN_GAPS {
                "insufficient-spacing-evidence"
            } else {
                "non-periodic-candidate"
            }
            .into(),
            gap_examples: examples,
        }
    }
}

#[derive(Default)]
pub(crate) struct Collector {
    groups: HashMap<(Kind, u64), Group>,
    raw_votes: [u64; 2],
    untracked_votes: [u64; 2],
    untracked_hits: [u64; 2],
}
pub(crate) struct Report {
    pub stats: BTreeMap<String, GroupStats>,
    pub detection: Value,
    pub truncated: bool,
}
impl Collector {
    pub fn observe(&mut self, kind: Kind, klass: u64, offset: u64, vote: bool) {
        let slot = kind.slot();
        self.raw_votes[slot] += u64::from(vote);
        if self.groups.len() == MAX_GROUPS && !self.groups.contains_key(&(kind, klass)) {
            self.untracked_votes[slot] += u64::from(vote);
            self.untracked_hits[slot] += 1;
            return;
        }
        let group = self.groups.entry((kind, klass)).or_insert_with(|| Group {
            rng: klass ^ ((slot as u64) << 63),
            ..Default::default()
        });
        group.observe(offset, vote);
    }
    pub fn finish(self) -> Report {
        let mut stats = BTreeMap::new();
        let mut excluded = [0; 2];
        let mut retained = [0; 2];
        for ((kind, klass), group) in self.groups {
            let group = group.finish();
            if group.periodic {
                excluded[kind.slot()] += group.detection_votes;
            } else {
                retained[kind.slot()] += group.detection_votes;
            }
            stats.insert(format!("{}:0x{klass:x}", kind.name()), group);
        }
        let mut detection = analysis::detection(retained[0], retained[1]);
        detection["method"] = json!("spacing-filter-v1");
        detection["raw_votes"] = json!({"wide":self.raw_votes[0],"narrow":self.raw_votes[1]});
        detection["excluded_periodic_votes"] = json!({"wide":excluded[0],"narrow":excluded[1]});
        detection["untracked_votes"] =
            json!({"wide":self.untracked_votes[0],"narrow":self.untracked_votes[1]});
        detection["untracked_group_hits"] =
            json!({"wide":self.untracked_hits[0],"narrow":self.untracked_hits[1]});
        detection["spacing_policy"] = json!({"max_groups":MAX_GROUPS,"reservoir_gaps_per_group":SAMPLE_GAPS,
            "minimum_sampled_gaps":MIN_GAPS,"periodic_when":"strictly more than 90% of sampled consecutive gaps equal the mode",
            "sampling":"deterministic whole-stream reservoir; medians and mode fractions are estimates when total_gaps > sampled_gaps"});
        let truncated = self.untracked_hits.iter().any(|&n| n > 0);
        if self.untracked_votes.iter().any(|&n| n > 0) {
            detection["suggestion"] = json!("inconclusive");
            detection["abstention_reason"] = json!(
                "group limit dropped detection-eligible hits; retained vote share cannot establish the capture profile"
            );
        } else if retained.iter().sum::<u64>() < 32 {
            detection["abstention_reason"] =
                json!("fewer than 32 non-periodic detection votes remain");
        }
        detection["retained_vote_share"] = detection["confidence"].clone();
        if detection["suggestion"] == "inconclusive" {
            detection["confidence"] = Value::Null;
        }
        detection["caveat"] = json!(
            "Periodicity is not proof of metadata: contiguous real objects can be periodic too. Non-periodic words can still be junk. Wide/narrow hypotheses may vote at the same offset. Confidence is a retained vote share, not probability or JVM-flag verification."
        );
        Report {
            stats,
            detection,
            truncated,
        }
    }
}

pub(crate) fn validate(stats: &GroupStats, heap_bytes: u64) -> bool {
    stats.hits > 0
        && stats.hits <= heap_bytes / 8
        && stats.detection_votes <= stats.hits
        && stats.total_gaps == stats.hits - 1
        && stats.sampled_gaps <= SAMPLE_GAPS
        && stats.sampled_gaps as u64 == stats.total_gaps.min(SAMPLE_GAPS as u64)
        && stats.mode_sample_count <= stats.sampled_gaps
        && stats.first_offset <= stats.last_offset
        && stats.last_offset < heap_bytes
        && stats.gap_examples.len() <= EXAMPLES
        && stats.gap_examples.iter().all(|g| {
            g.from >= stats.first_offset
                && g.to <= stats.last_offset
                && g.to.checked_sub(g.from) == Some(g.gap)
                && g.gap > 0
        })
}

pub(crate) fn summary_groups(
    stats: &BTreeMap<String, GroupStats>,
) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let mut groups: Vec<_> = stats.iter().collect();
    groups.sort_by(|(ka, a), (kb, b)| b.hits.cmp(&a.hits).then(ka.cmp(kb)));
    let (mut objects, mut periodic, mut unclassified) = (Vec::new(), Vec::new(), Vec::new());
    for (key, stats) in groups {
        let target = if stats.periodic {
            &mut periodic
        } else if stats.sampled_gaps < MIN_GAPS {
            &mut unclassified
        } else {
            &mut objects
        };
        if target.len() < 20 {
            target.push(json!({"group":key,"hits":stats.hits,"detection_votes":stats.detection_votes,
                "first_offset":stats.first_offset,"last_offset":stats.last_offset,"sampled_gaps":stats.sampled_gaps,
                "median_gap":stats.median_gap,"mode_gap":stats.mode_gap,"mode_fraction":stats.mode_fraction,
                "periodic":stats.periodic,"classification":stats.classification}));
        }
    }
    (objects, periodic, unclassified)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_440_byte_spacing_is_removed_from_votes() {
        let mut c = Collector::default();
        for i in 0..10000 {
            c.observe(Kind::Narrow, 0x1000, 272 + i * 440, true);
        }
        let r = c.finish();
        let s = &r.stats["narrow:0x1000"];
        assert_eq!(s.hits, 10000);
        assert_eq!(s.median_gap, Some(440.0));
        assert_eq!(s.mode_gap, Some(440));
        assert!(s.periodic);
        assert_eq!(s.sampled_gaps, SAMPLE_GAPS);
        assert_eq!(r.detection["excluded_periodic_votes"]["narrow"], 10000);
        assert_eq!(r.detection["narrow_votes"], 0);
        assert_eq!(r.detection["suggestion"], "inconclusive");
        assert!(s.gap_examples.iter().any(|g| g.to > 3_000_000));
    }
    #[test]
    fn threshold_is_strict_and_small_samples_are_unclassified() {
        let mut g = Group::default();
        g.observe(0, true);
        let mut offset = 0;
        for i in 0..40 {
            offset += if i < 36 { 440 } else { 448 };
            g.observe(offset, true);
        }
        let s = g.finish();
        assert_eq!(s.mode_fraction, Some(0.9));
        assert!(!s.periodic);
        let mut g = Group::default();
        for i in 0..32 {
            g.observe(i * 440, true);
        }
        let s = g.finish();
        assert!(!s.periodic);
        assert_eq!(s.classification, "insufficient-spacing-evidence");
        let mut g = Group::default();
        for i in 0..34 {
            g.observe(i * 440, true);
        }
        assert!(g.finish().periodic);
    }
    #[test]
    fn reservoir_does_not_classify_only_the_first_prefix() {
        let mut g = Group::default();
        let mut offset = 0;
        for i in 0..20000 {
            g.observe(offset, true);
            offset += if i < 1000 { 440 } else { 24 + 8 * (i % 11) };
        }
        let s = g.finish();
        assert!(!s.periodic);
        assert!(s.mode_fraction.unwrap() < 0.3);
    }
    #[test]
    fn dropped_groups_and_vote_predicates_are_accounted_for() {
        let mut c = Collector::default();
        for i in 0..MAX_GROUPS as u64 {
            c.observe(Kind::Narrow, 0x1000 + i, i * 32, false);
        }
        c.observe(Kind::Narrow, 0x9000, MAX_GROUPS as u64 * 32, true);
        let r = c.finish();
        assert!(r.truncated);
        assert_eq!(r.stats.len(), MAX_GROUPS);
        assert_eq!(r.detection["untracked_votes"]["narrow"], 1);
        assert_eq!(r.detection["raw_votes"]["narrow"], 1);
        assert_eq!(r.detection["suggestion"], "inconclusive");
        assert_eq!(r.stats["narrow:0x1000"].detection_votes, 0);
    }
}
