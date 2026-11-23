package shared

import (
	"testing"
	"time"
)

func TestRecordOnlyShapesLengthsWithoutArtificialDelay(t *testing.T) {
	options := normalizedRecordShapingOptions(RecordShapingOptions{
		SenderPacingMode: SenderPacingRecordOnly,
		CoalesceMin:      4 * time.Millisecond,
		CoalesceMax:      8 * time.Millisecond,
		MaxPacing:        16 * time.Millisecond,
	})

	if options.CoalesceMin != 0 || options.CoalesceMax != 0 || options.MaxPacing != 0 {
		t.Fatalf(
			"record-only mode retained timing delays: min=%s max=%s pacing=%s",
			options.CoalesceMin,
			options.CoalesceMax,
			options.MaxPacing,
		)
	}

	plan := PlanExternalRecordShape(64*1024, 1, options)
	if len(plan.Chunks) < 2 {
		t.Fatalf("record-only mode stopped shaping record lengths: %#v", plan.Chunks)
	}
	if plan.CoalesceDelay != 0 || plan.PacingDelay != 0 {
		t.Fatalf("record-only plan added delay: %#v", plan)
	}
	for _, chunk := range plan.Chunks {
		if chunk <= 0 || chunk > ExternalRecordMaxChunk {
			t.Fatalf("invalid shaped chunk size %d in %#v", chunk, plan.Chunks)
		}
	}
}

func TestUserspaceModeKeepsBoundedTimingDefaults(t *testing.T) {
	options := normalizedRecordShapingOptions(RecordShapingOptions{
		SenderPacingMode: SenderPacingUserspace,
	})

	if options.CoalesceMax != 8*time.Millisecond {
		t.Fatalf("unexpected coalescing default: %s", options.CoalesceMax)
	}
	if options.MaxPacing != 16*time.Millisecond {
		t.Fatalf("unexpected pacing default: %s", options.MaxPacing)
	}
}

// With browser records a batch is written whole, whatever its size, so TLS
// fills records to the maximum the way Chrome does; without the option the
// earlier random splitting still applies.
func TestBrowserRecordsWriteBatchesWhole(t *testing.T) {
	for _, size := range []int{1, 900, 16 * 1024, 100 * 1024, 900 * 1024} {
		plan := PlanExternalRecordShape(size, uint64(size)*7919, RecordShapingOptions{
			SenderPacingMode: SenderPacingRecordOnly,
			BrowserRecords:   true,
		})
		if len(plan.Chunks) != 1 || plan.Chunks[0] != size || plan.PacingDelay != 0 {
			t.Fatalf("size %d planned as %+v, want one whole write without pacing", size, plan)
		}
	}
	split := PlanExternalRecordShape(100*1024, 42, RecordShapingOptions{SenderPacingMode: SenderPacingRecordOnly})
	if len(split.Chunks) < 2 {
		t.Fatalf("default record shaping no longer splits large writes: %+v", split)
	}
}
