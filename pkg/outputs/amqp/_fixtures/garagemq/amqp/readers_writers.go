package amqp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/pool"
	"io"
	"time"
)

var emptyBufferPool = pool.NewBufferPool(0)

// 14 bytes for class-id | weight | body size | property flags
var headerBufferPool = pool.NewBufferPool(14)

// AmqpHeader standard AMQP header
var AmqpHeader = []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}

// supported protocol identifiers
const (
	Proto091    = "amqp-0-9-1"
	ProtoRabbit = "amqp-rabbit"
)

func writeSlice(wr io.Writer, data []byte) error {
	_, err := wr.Write(data[:])
	return err
}

/*
ReadFrame reads and parses raw data from conn reader and returns amqp frame

@spec-note
All frames consist of a header (7 octets), a payload of arbitrary size, and a
'frame-end' octet that detects malformed frames:

	0      1         3             7                  size+7 size+8
	+------+---------+-------------+  +------------+  +-----------+
	| type | channel |     size    |  |  payload   |  | frame-end |
	+------+---------+-------------+  +------------+  +-----------+
	 octet   short         long         size octets       octet

To read a frame, we:
 1. Read the header and check the frame type and channel.
 2. Depending on the frame size, we read the payload
 3. Read the frame-end octet.
*/
func ReadFrame(r io.Reader) (frame *Frame, err error) {
	// It does not matter that we call read methods 3 time
	// Because net.TCPConn connection buffered by bufio.NewReader
	frame = &Frame{}
	if frame.Type, err = ReadOctet(r); err != nil {
		return nil, err
	}
	if frame.ChannelID, err = ReadShort(r); err != nil {
		return nil, err
	}
	var payloadSize uint32
	if payloadSize, err = ReadLong(r); err != nil {
		return nil, err
	}

	var payload = make([]byte, payloadSize+1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	frame.Payload = payload[0:payloadSize]

	// check frame end
	if payload[payloadSize] != FrameEnd {
		return nil, fmt.Errorf(
			"the frame-end octet MUST always be the hexadecimal value 'xCE', %x given",
			payload[payloadSize])
	}

	return frame, nil
}

// WriteFrame pack amqp Frame as bytes and write to conn writer
func WriteFrame(wr io.Writer, frame *Frame) (err error) {
	if err = WriteOctet(wr, frame.Type); err != nil {
		return err
	}
	if err = WriteShort(wr, frame.ChannelID); err != nil {
		return err
	}

	// size + payload
	if err = WriteLongstr(wr, frame.Payload); err != nil {
		return err
	}
	// frame end
	if err = WriteOctet(wr, FrameEnd); err != nil {
		return err
	}

	return nil
}

// ReadOctet reads octet (byte)
func ReadOctet(r io.Reader) (data byte, err error) {
	var b [1]byte
	if _, err = io.ReadFull(r, b[:]); err != nil {
		return
	}
	data = b[0]
	return
}

// WriteOctet writes octet (byte)
func WriteOctet(wr io.Writer, data byte) error {
	var b [1]byte
	b[0] = data
	return writeSlice(wr, b[:])
}

// ReadShort reads 2 bytes
func ReadShort(r io.Reader) (data uint16, err error) {
	err = binary.Read(r, binary.BigEndian, &data)
	return
}

// WriteShort writes 2 bytes
func WriteShort(wr io.Writer, data uint16) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], data)
	return writeSlice(wr, b[:])
}

// ReadLong reads 4 bytes
func ReadLong(r io.Reader) (data uint32, err error) {
	err = binary.Read(r, binary.BigEndian, &data)
	return
}

// WriteLong writes 4 bytes
func WriteLong(wr io.Writer, data uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], data)
	return writeSlice(wr, b[:])
}

// ReadLonglong reads 8 bytes
func ReadLonglong(r io.Reader) (data uint64, err error) {
	err = binary.Read(r, binary.BigEndian, &data)
	return
}

// WriteLonglong writes 8 bytes
func WriteLonglong(wr io.Writer, data uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], data)
	return writeSlice(wr, b[:])
}

// ReadTimestamp reads timestamp
// amqp presents timestamp as 8byte int
func ReadTimestamp(r io.Reader) (data time.Time, err error) {
	var seconds uint64
	if seconds, err = ReadLonglong(r); err != nil {
		return
	}
	return time.Unix(int64(seconds), 0), nil
}

// WriteTimestamp writes timestamp
func WriteTimestamp(wr io.Writer, data time.Time) error {
	return WriteLonglong(wr, uint64(data.Unix()))
}

// ReadShortstr reads string
func ReadShortstr(r io.Reader) (data string, err error) {
	var length byte

	length, err = ReadOctet(r)
	if err != nil {
		return "", err
	}

	strBytes := make([]byte, length)

	_, err = io.ReadFull(r, strBytes)
	if err != nil {
		return "", err
	}
	data = string(strBytes)
	return
}

// WriteShortstr writes string
func WriteShortstr(wr io.Writer, data string) error {
	if err := WriteOctet(wr, byte(len(data))); err != nil {
		return err
	}
	if _, err := wr.Write([]byte(data)); err != nil {
		return err
	}

	return nil
}

// ReadLongstr reads long string
// Long string is just array of bytes
func ReadLongstr(r io.Reader) (data []byte, err error) {
	var length uint32

	length, err = ReadLong(r)
	if err != nil {
		return nil, err
	}

	data = make([]byte, length)

	_, err = io.ReadFull(r, data)
	if err != nil {
		return nil, err
	}
	return
}

// WriteLongstr writes long string
func WriteLongstr(wr io.Writer, data []byte) error {
	err := WriteLong(wr, uint32(len(data)))
	if err != nil {
		return err
	}
	_, err = wr.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// ReadTable reads amqp table
// Standard amqp table and rabbitmq table are little different
// So we have second argument protoVersion to handle that issue
func ReadTable(r io.Reader, protoVersion string) (data *Table, err error) {
	tmpData := Table{}
	tableData, err := ReadLongstr(r)
	if err != nil {
		return nil, err
	}

	tableReader := bytes.NewReader(tableData)
	for tableReader.Len() > 0 {
		var key string
		var value interface{}
		if key, err = ReadShortstr(tableReader); err != nil {
			return nil, errors.New("Unable to read key from table: " + err.Error())
		}

		if value, err = readV(tableReader, protoVersion); err != nil {
			return nil, errors.New("Unable to read value from table: " + err.Error())
		}

		tmpData[key] = value
	}

	return &tmpData, nil
}

func readV(r io.Reader, protoVersion string) (data interface{}, err error) {
	switch protoVersion {
	case Proto091:
		return readValue091(r)
	case ProtoRabbit:
		return readValueRabbit(r)
	}

	return nil, fmt.Errorf("unknown proto version [%s]", protoVersion)
}

/*
Standard amqp-0-9-1 table fields

't' bool			boolean
'b' int8			short-short-int
'B' uint8			short-short-uint
'U' int16			short-int
'u' uint16			short-uint
'I' int32			long-int
'i' uint32			long-uint
'L' int64			long-long-int
'l' uint64			long-long-uint
'f' float			float
'd' double			double
'D' Decimal			decimal-value
's' string			short-string
'S'	[]byte			long-string
'A' []interface{} 	field-array
'T' time.Time		timestamp
'F' Table			field-table
'V' nil				no-field
*/
func readValue091(r io.Reader) (data interface{}, err error) {
	vType, err := ReadOctet(r)
	if err != nil {
		return nil, err
	}

	switch vType {
	case 't':
		var rData byte
		rData, err = ReadOctet(r)
		if err != nil {
			return nil, err
		}
		return rData != 0, nil
	case 'b':
		var rData int8
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'B':
		var rData uint8
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'U':
		var rData int16
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'u':
		var rData uint16
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'I':
		var rData int32
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'i':
		var rData uint32
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'L':
		var rData int64
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'l':
		var rData uint64
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'f':
		var rData float32
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'd':
		var rData float64
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'D':
		var rData = Decimal{0, 0}

		if err = binary.Read(r, binary.BigEndian, &rData.Scale); err != nil {
			return nil, err
		}
		if err = binary.Read(r, binary.BigEndian, &rData.Value); err != nil {
			return nil, err
		}
		return rData, nil
	case 's':
		var rData string
		if rData, err = ReadShortstr(r); err == nil {
			return nil, err
		}

		return rData, nil
	case 'S':
		var rData []byte
		if rData, err = ReadLongstr(r); err == nil {
			return nil, err
		}

		return rData, nil
	case 'T':
		var rData time.Time
		if rData, err = ReadTimestamp(r); err == nil {
			return nil, err
		}

		return rData, nil
	case 'A':
		var rData []interface{}
		if rData, err = readArray(r, Proto091); err == nil {
			return nil, err
		}
		return rData, nil
	case 'F':
		var rData *Table
		if rData, err = ReadTable(r, Proto091); err == nil {
			return nil, err
		}
		return rData, nil
	case 'V':
		return nil, nil
	}

	return nil, fmt.Errorf("unsupported type %c (%d) by %s protocol", vType, vType, Proto091)
}

/*
Rabbitmq table fields

't' bool			boolean
'b' int8			short-short-int
's'	int16			short-int
'I' int32			long-int
'l' int64			long-long-int
'f' float			float
'd' double			double
'D' Decimal			decimal-value
'S'	[]byte			long-string
'T' time.Time		timestamp
'F' Table			field-table
'V' nil				no-field
'x' []interface{} 	field-array
*/
func readValueRabbit(r io.Reader) (data interface{}, err error) {
	vType, err := ReadOctet(r)
	if err != nil {
		return nil, err
	}

	switch vType {
	case 't':
		var rData byte
		rData, err = ReadOctet(r)
		if err != nil {
			return nil, err
		}
		return rData != 0, nil
	case 'b':
		var rData int8
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 's':
		var rData int16
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'I':
		var rData int32
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'l':
		var rData int64
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'f':
		var rData float32
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'd':
		var rData float64
		if err = binary.Read(r, binary.BigEndian, &rData); err != nil {
			return nil, err
		}
		return rData, nil
	case 'D':
		var rData = Decimal{0, 0}

		if err = binary.Read(r, binary.BigEndian, &rData.Scale); err != nil {
			return nil, err
		}
		if err = binary.Read(r, binary.BigEndian, &rData.Value); err != nil {
			return nil, err
		}
		return rData, nil
	case 'S':
		var rData []byte
		if rData, err = ReadLongstr(r); err != nil {
			return nil, err
		}

		return string(rData), nil
	case 'T':
		var rData time.Time
		if rData, err = ReadTimestamp(r); err != nil {
			return nil, err
		}

		return rData, nil
	case 'x':
		var rData []interface{}
		if rData, err = readArray(r, ProtoRabbit); err != nil {
			return nil, err
		}
		return rData, nil
	case 'F':
		var rData *Table
		if rData, err = ReadTable(r, ProtoRabbit); err != nil {
			return nil, err
		}
		return rData, nil
	case 'V':
		return nil, nil
	}

	return nil, fmt.Errorf("unsupported type %c (%d) by %s protocol", vType, vType, ProtoRabbit)
}

// WriteTable writes amqp table
// Standard amqp table and rabbitmq table are little different
// So we have second argument protoVersion to handle that issue
func WriteTable(writer io.Writer, table *Table, protoVersion string) (err error) {
	var buf = emptyBufferPool.Get()
	defer emptyBufferPool.Put(buf)
	for key, v := range *table {
		if err := WriteShortstr(buf, key); err != nil {
			return err
		}
		if err := writeV(buf, v, protoVersion); err != nil {
			return err
		}
	}
	return WriteLongstr(writer, buf.Bytes())
}

func writeV(writer io.Writer, v interface{}, protoVersion string) (err error) {
	switch protoVersion {
	case Proto091:
		return writeValue091(writer, v)
	case ProtoRabbit:
		return writeValueRabbit(writer, v)
	}

	return fmt.Errorf("unknown proto version [%s]", protoVersion)
}

/*
Standard amqp-0-9-1 table fields

't' bool			boolean
'b' int8			short-short-int
'B' uint8			short-short-uint
'U' int16			short-int
'u' uint16			short-uint
'I' int32			long-int
'i' uint32			long-uint
'L' int64			long-long-int
'l' uint64			long-long-uint
'f' float			float
'd' double			double
'D' Decimal			decimal-value
's' string			short-string
'S'	[]byte			long-string
'A' []interface{} 	field-array
'T' time.Time		timestamp
'F' Table			field-table
'V' nil				no-field
*/
func writeValue091(writer io.Writer, v interface{}) (err error) {
	switch value := v.(type) {
	case bool:
		if err = WriteOctet(writer, byte('t')); err == nil {
			if value {
				err = binary.Write(writer, binary.BigEndian, uint8(1))
			} else {
				err = binary.Write(writer, binary.BigEndian, uint8(0))
			}
		}
	case int8:
		if err = WriteOctet(writer, byte('b')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint8:
		if err = WriteOctet(writer, byte('B')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case int16:
		if err = WriteOctet(writer, byte('U')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint16:
		if err = binary.Write(writer, binary.BigEndian, byte('u')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case int32:
		if err = binary.Write(writer, binary.BigEndian, byte('I')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint32:
		if err = binary.Write(writer, binary.BigEndian, byte('i')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case int64:
		if err = binary.Write(writer, binary.BigEndian, byte('L')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint64:
		if err = binary.Write(writer, binary.BigEndian, byte('l')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case float32:
		if err = binary.Write(writer, binary.BigEndian, byte('f')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case float64:
		if err = binary.Write(writer, binary.BigEndian, byte('d')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case Decimal:
		if err = binary.Write(writer, binary.BigEndian, byte('D')); err == nil {
			if err = binary.Write(writer, binary.BigEndian, byte(value.Scale)); err == nil {
				err = binary.Write(writer, binary.BigEndian, uint32(value.Value))
			}
		}
	case string:
		if err = WriteOctet(writer, byte('s')); err == nil {
			err = WriteShortstr(writer, value)
		}
	case []byte:
		if err = WriteOctet(writer, byte('S')); err == nil {
			err = WriteLongstr(writer, value)
		}
	case time.Time:
		if err = WriteOctet(writer, byte('T')); err == nil {
			err = WriteTimestamp(writer, value)
		}
	case []interface{}:
		if err = WriteOctet(writer, byte('A')); err == nil {
			err = writeArray(writer, value, Proto091)
		}

	case Table:
		if err = WriteOctet(writer, byte('F')); err == nil {
			err = WriteTable(writer, &value, Proto091)
		}
	case nil:
		err = binary.Write(writer, binary.BigEndian, byte('V'))
	default:
		err = fmt.Errorf("unsupported type by %s protocol", Proto091)
	}

	return
}

/*
Rabbitmq table fields

't' bool			boolean
'b' int8			short-short-int
's'	int16			short-int
'I' int32			long-int
'l' int64			long-long-int
'f' float			float
'd' double			double
'D' Decimal			decimal-value
'S'	[]byte			long-string
'T' time.Time		timestamp
'F' Table			field-table
'V' nil				no-field
'x' []interface{} 	field-array
*/
func writeValueRabbit(writer io.Writer, v interface{}) (err error) {
	switch value := v.(type) {
	case bool:
		if err = WriteOctet(writer, byte('t')); err == nil {
			if value {
				err = binary.Write(writer, binary.BigEndian, uint8(1))
			} else {
				err = binary.Write(writer, binary.BigEndian, uint8(0))
			}
		}
	case int8:
		if err = WriteOctet(writer, byte('b')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint8:
		if err = WriteOctet(writer, byte('b')); err == nil {
			err = binary.Write(writer, binary.BigEndian, int8(value))
		}
	case int16:
		if err = WriteOctet(writer, byte('s')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint16:
		if err = binary.Write(writer, binary.BigEndian, byte('s')); err == nil {
			err = binary.Write(writer, binary.BigEndian, int16(value))
		}
	case int32:
		if err = binary.Write(writer, binary.BigEndian, byte('I')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint32:
		if err = binary.Write(writer, binary.BigEndian, byte('I')); err == nil {
			err = binary.Write(writer, binary.BigEndian, int32(value))
		}
	case int64:
		if err = binary.Write(writer, binary.BigEndian, byte('l')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case uint64:
		if err = binary.Write(writer, binary.BigEndian, byte('l')); err == nil {
			err = binary.Write(writer, binary.BigEndian, int64(value))
		}
	case float32:
		if err = binary.Write(writer, binary.BigEndian, byte('f')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case float64:
		if err = binary.Write(writer, binary.BigEndian, byte('d')); err == nil {
			err = binary.Write(writer, binary.BigEndian, value)
		}
	case Decimal:
		if err = binary.Write(writer, binary.BigEndian, byte('D')); err == nil {
			if err = binary.Write(writer, binary.BigEndian, byte(value.Scale)); err == nil {
				err = binary.Write(writer, binary.BigEndian, uint32(value.Value))
			}
		}
	case []byte:
		if err = WriteOctet(writer, byte('S')); err == nil {
			err = WriteLongstr(writer, value)
		}
	case string:
		if err = WriteOctet(writer, byte('S')); err == nil {
			err = WriteLongstr(writer, []byte(value))
		}
	case time.Time:
		if err = WriteOctet(writer, byte('T')); err == nil {
			err = WriteTimestamp(writer, value)
		}
	case []interface{}:
		if err = WriteOctet(writer, byte('x')); err == nil {
			err = writeArray(writer, value, ProtoRabbit)
		}
	case Table:
		if err = WriteOctet(writer, byte('F')); err == nil {
			err = WriteTable(writer, &value, ProtoRabbit)
		}
	case nil:
		err = binary.Write(writer, binary.BigEndian, byte('V'))
	default:
		err = fmt.Errorf("unsupported type by %s protocol", Proto091)
	}

	return
}

func writeArray(writer io.Writer, array []interface{}, protoVersion string) error {
	var buf = emptyBufferPool.Get()
	defer emptyBufferPool.Put(buf)

	for _, v := range array {
		if err := writeV(buf, v, protoVersion); err != nil {
			return err
		}
	}
	return WriteLongstr(writer, buf.Bytes())
}

func readArray(r io.Reader, protoVersion string) (data []interface{}, err error) {
	data = make([]interface{}, 0)
	var arrayData []byte
	if arrayData, err = ReadLongstr(r); err != nil {
		return nil, err
	}

	arrayBuffer := bytes.NewBuffer(arrayData)
	for arrayBuffer.Len() > 0 {
		var itemV interface{}
		if itemV, err = readV(arrayBuffer, protoVersion); err != nil {
			return nil, err
		}

		data = append(data, itemV)
	}

	return data, nil
}

/*
ReadContentHeader reads amqp content header

Certain methods (such as Basic.Publish, Basic.Deliver, etc.) are formally
defined as carrying content.  When a peer sends such a method frame, it always
follows it with a content header and zero or more content body frames.

A content header frame has this format:

	0          2        4           12               14
	+----------+--------+-----------+----------------+------------- - -
	| class-id | weight | body size | property flags | property list...
	+----------+--------+-----------+----------------+------------- - -
	  short     short    long long       short        remainder...
*/
func ReadContentHeader(r io.Reader, protoVersion string) (*ContentHeader, error) {
	var err error
	// 14 bytes for class-id | weight | body size | property flags
	headerBuf := headerBufferPool.Get()
	defer headerBufferPool.Put(headerBuf)

	var header [14]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if _, err = headerBuf.Write(header[:]); err != nil {
		return nil, err
	}

	contentHeader := &ContentHeader{}

	if contentHeader.ClassID, err = ReadShort(headerBuf); err != nil {
		return nil, err
	}
	if contentHeader.Weight, err = ReadShort(headerBuf); err != nil {
		return nil, err
	}
	if contentHeader.BodySize, err = ReadLonglong(headerBuf); err != nil {
		return nil, err
	}
	if contentHeader.propertyFlags, err = ReadShort(headerBuf); err != nil {
		return nil, err
	}

	contentHeader.PropertyList = &BasicPropertyList{}
	if err = contentHeader.PropertyList.Read(r, contentHeader.propertyFlags, protoVersion); err != nil {
		return nil, err
	}

	return contentHeader, nil
}

// WriteContentHeader writes amqp content header
func WriteContentHeader(writer io.Writer, header *ContentHeader, protoVersion string) (err error) {
	if err = WriteShort(writer, header.ClassID); err != nil {
		return err
	}
	if err = WriteShort(writer, header.Weight); err != nil {
		return err
	}
	if err = WriteLonglong(writer, header.BodySize); err != nil {
		return err
	}

	var propertyBuf = emptyBufferPool.Get()
	defer emptyBufferPool.Put(propertyBuf)

	properyFlags, err := header.PropertyList.Write(propertyBuf, protoVersion)
	if err != nil {
		return err
	}

	header.propertyFlags = properyFlags
	if err = WriteShort(writer, header.propertyFlags); err != nil {
		return err
	}
	if _, err = writer.Write(propertyBuf.Bytes()); err != nil {
		return err
	}

	return
}
