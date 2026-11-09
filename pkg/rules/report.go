package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// Event groups that don't map to an event category, but that the event
// source needs to know about to enable the corresponding instrumentation.
var (
	vaMapEvents    = []event.Type{event.MapViewOfSection, event.UnmapViewOfSection}
	auditAPIEvents = []event.Type{
		event.OpenProcess,
		event.OpenThread,
		event.SetThreadContext,
		event.CreateSymbolicLinkObject,
	}
)

// RuleSetReport is the outcome of building the rule set. It describes which
// event types (and therefore categories) the rules reference, the approvers
// derived from the rules, and the rules that were discarded. The event source
// consults the report to enable only the providers and events required by the
// rules, and to drop all other events as soon as they are consumed from the
// session buffer.
//
// The set of used events is the single source of truth. Categories and the
// other groupings are derived from it, so they can never drift apart.
type RuleSetReport struct {
	// UsedEvents contains the unique event types that appear in the rules,
	// sorted in ascending order.
	UsedEvents []event.Type
	// NumberRules is the number of rules in the rule set.
	NumberRules int
	// Approvers are the approvers derived from the rules.
	Approvers *Approvers
	// Discarded are the rules that were valid, but not added to the rule set.
	Discarded []DiscardedRule
}

// DiscardedRule is a rule that compiled successfully but the rule set
// decided not to run it, together with the reason.
type DiscardedRule struct {
	// Name is the rule name.
	Name string
	// Source is the policy the rule comes from.
	Source string
	// Reason explains why the rule is discarded.
	Reason string
}

// buildReport computes the report from the event types referenced by the rules.
func buildReport(rules []*Rule) *RuleSetReport {
	var types []event.Type
	for _, r := range rules {
		types = append(types, r.GetEventTypes()...)
	}
	slices.Sort(types)

	return &RuleSetReport{
		NumberRules: len(rules),
		UsedEvents:  slices.Compact(types),
	}
}

// ContainsEvent determines if any rule in the rule set can match the event type.
func (r *RuleSetReport) ContainsEvent(typ event.Type) bool {
	if r == nil {
		return false
	}
	_, found := slices.BinarySearch(r.UsedEvents, typ)
	return found
}

// ContainsAny determines if any of the given event types is used by the rules.
func (r *RuleSetReport) ContainsAny(types ...event.Type) bool {
	return slices.ContainsFunc(types, r.ContainsEvent)
}

// HasCategory determines if any rule references an event of the given category.
func (r *RuleSetReport) HasCategory(category event.Category) bool {
	if r == nil {
		return false
	}
	return slices.ContainsFunc(r.UsedEvents, func(typ event.Type) bool {
		return event.GetTypeInfo(typ).Category == category
	})
}

// Categories returns the distinct categories of the events used by the rules.
func (r *RuleSetReport) Categories() []event.Category {
	if r == nil {
		return nil
	}
	var categories []event.Category
	for _, typ := range r.UsedEvents {
		if c := event.GetTypeInfo(typ).Category; !slices.Contains(categories, c) {
			categories = append(categories, c)
		}
	}
	return categories
}

// Convenience predicates consumed by the event source.

func (r *RuleSetReport) HasProcEvents() bool     { return r.HasCategory(event.Process) }
func (r *RuleSetReport) HasThreadEvents() bool   { return r.HasCategory(event.Thread) }
func (r *RuleSetReport) HasModuleEvents() bool   { return r.HasCategory(event.Module) }
func (r *RuleSetReport) HasFileEvents() bool     { return r.HasCategory(event.File) }
func (r *RuleSetReport) HasNetworkEvents() bool  { return r.HasCategory(event.Network) }
func (r *RuleSetReport) HasRegistryEvents() bool { return r.HasCategory(event.Registry) }
func (r *RuleSetReport) HasMemEvents() bool      { return r.HasCategory(event.Memory) }
func (r *RuleSetReport) HasVAMapEvents() bool    { return r.ContainsAny(vaMapEvents...) }
func (r *RuleSetReport) HasAuditAPIEvents() bool { return r.ContainsAny(auditAPIEvents...) }

// HasDNSEvents determines if any rule references an event of the DNS subcategory.
func (r *RuleSetReport) HasDNSEvents() bool {
	if r == nil {
		return false
	}
	return slices.ContainsFunc(r.UsedEvents, func(typ event.Type) bool {
		return event.GetTypeInfo(typ).Subcategory == event.DNS
	})
}

// Covers determines if all the events used by the other report are also used
// by this one. It is the case when the rule set reload doesn't need any event
// that the event source wasn't configured to capture.
func (r *RuleSetReport) Covers(other *RuleSetReport) bool {
	return len(r.Missing(other)) == 0
}

// Missing returns the event types used by the other report that are not used
// by this one.
func (r *RuleSetReport) Missing(other *RuleSetReport) []event.Type {
	if other == nil {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(other.UsedEvents), r.ContainsEvent)
}

// String returns the summary used in the logs.
func (r *RuleSetReport) String() string {
	if r == nil {
		return "<nil>"
	}
	names := make([]string, len(r.UsedEvents))
	for i, typ := range r.UsedEvents {
		names[i] = typ.String()
	}
	slices.Sort(names)

	return fmt.Sprintf("rules=%d discarded=%d categories=%v events=[%s]",
		r.NumberRules,
		len(r.Discarded),
		r.Categories(),
		strings.Join(names, ", "),
	)
}
