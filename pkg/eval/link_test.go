package eval

import (
	"fmt"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/stretchr/testify/assert"
)

func TestMakeSequenceLinkID(t *testing.T) {
	var tests = []struct {
		valuer  *ValuerCache
		seqLink *ast.SequenceLink
		id      any
	}{
		{&ValuerCache{Valuer: ast.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"}},
			&ast.SequenceLink{Fields: []*ast.FieldLiteral{{Value: "ps.exe"}, {Value: "ps.uuid"}}},
			"433a5c57696e646f77735c53797374656d33325c636d642e65786544556ea343cfb501",
		},
		{&ValuerCache{Valuer: ast.MapValuer{
			"ps.uuid":        uint64(123232454234232132),
			"module.address": uint64(0xfff32343)}},
			&ast.SequenceLink{Fields: []*ast.FieldLiteral{{Value: "ps.uuid"}, {Value: "module.address"}}},
			"44556ea343cfb5014323f3ff00000000",
		},
		{&ValuerCache{Valuer: ast.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"}},
			&ast.SequenceLink{Fields: []*ast.FieldLiteral{{Value: "ps.exe"}}},
			"C:\\Windows\\System32\\cmd.exe",
		},
		{&ValuerCache{Valuer: ast.MapValuer{
			"ps.uuid": uint64(123232454234232132),
			"ps.exe":  "C:\\Windows\\System32\\cmd.exe"}},
			&ast.SequenceLink{Fields: []*ast.FieldLiteral{{Value: "ps.uuid"}}},
			uint64(123232454234232132),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.valuer), func(t *testing.T) {
			assert.Equal(t, tt.id, MakeSequenceLinkID(tt.valuer, tt.seqLink))
			tt.valuer.Release()
		})
	}
}
