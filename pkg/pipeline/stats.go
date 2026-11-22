package pipeline

// Stats is a snapshot of the whole pipeline.
type Stats struct {
	Sources []SourceStats
	Reorder ReorderStats
	// PendingHigh is the high-water mark of the reorderer's length. Compare
	// with MaxPending to size it.
	PendingHigh int
	// Panics is the number of Sink.Handle panics recovered.
	Panics uint64
}
