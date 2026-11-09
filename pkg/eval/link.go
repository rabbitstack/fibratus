package eval

import (
	"encoding/hex"
	"net"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
)

func MakeSequenceLinkID(valuer *ValuerCache, link *ast.SequenceLink) any {
	if !link.IsCompound() {
		return valuer.Valuer[link.First()]
	}

	values := make([]any, 0, len(link.Fields))
	for _, fld := range link.Fields {
		values = append(values, valuer.Valuer[fld.Value])
	}

	buf := make([]byte, 0)
	for _, v := range values {
		switch val := v.(type) {
		case uint8:
			buf = append(buf, val)
		case uint16:
			buf = append(buf, bytes.WriteUint16(val)...)
		case uint32:
			buf = append(buf, bytes.WriteUint32(val)...)
		case uint64:
			buf = append(buf, bytes.WriteUint64(val)...)
		case int8:
			buf = append(buf, byte(val))
		case int16:
			buf = append(buf, bytes.WriteUint16(uint16(val))...)
		case int32:
			buf = append(buf, bytes.WriteUint32(uint32(val))...)
		case int64:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case int:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case uint:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case string:
			buf = append(buf, val...)
		case net.IP:
			buf = append(buf, val...)
		}
	}
	return hex.EncodeToString(buf)
}
