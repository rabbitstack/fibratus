package binding

import (
	"bytes"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"reflect"
	"regexp"
	"strings"
)

// MatchType is the x-match attribute in a binding argument table
type MatchType int

const (
	// MatchAll requires all registered arguments to match for routing
	MatchAll MatchType = iota
	// MatchAny requires any registered arguments to match for routing
	MatchAny
)

// Binding represents AMQP-binding
type Binding struct {
	Queue      string
	Exchange   string
	RoutingKey string
	Arguments  *amqp.Table
	regexp     *regexp.Regexp
	topic      bool
	MatchType  MatchType
}

// NewBinding returns new instance of Binding
func NewBinding(queue string, exchange string, routingKey string, arguments *amqp.Table, topic bool) (*Binding, error) {
	binding := &Binding{
		Queue:      queue,
		Exchange:   exchange,
		RoutingKey: routingKey,
		Arguments:  arguments,
		topic:      topic,
	}

	if topic {
		var err error
		if binding.regexp, err = buildRegexp(routingKey); err != nil {
			return nil, fmt.Errorf("bad topic routing key %s -- %s",
				routingKey,
				err.Error())
		}
	}

	if arguments == nil {
		return binding, nil
	}

	// @spec-note AMQP 0.9.1
	//
	// Any field starting with 'x-' other than 'x-match' is
	// reserved for future use and will be ignored.
	//
	// * 'all' implies that all the other pairs must match the headers
	// property of a message for that message to be routed (i.e. and AND match)
	// * 'any' implies that the message should be routed if any of the
	// fields in the headers property match one of the fields in the
	// arguments table (i.e. an OR match)
	//
	// We arbitrarily choose `all` as the default if none was provided
	// at binding time.
	xmatch, ok := (*arguments)["x-match"]
	if ok {
		if xmatch == "all" {
			binding.MatchType = MatchAll
		} else if xmatch == "any" {
			binding.MatchType = MatchAny
		} else {
			return nil, fmt.Errorf("Invalid x-match field value %s, expected all or any",
				xmatch)
		}
	} else {
		binding.MatchType = MatchAll
	}

	return binding, nil
}

// @todo may be better will be trie or dfa than regexp
// @see http://www.rabbitmq.com/blog/2010/09/14/very-fast-and-scalable-topic-routing-part-1/
// @see http://www.rabbitmq.com/blog/2011/03/28/very-fast-and-scalable-topic-routing-part-2/
//
// buildRegexp generate regexp from topic-match string
func buildRegexp(routingKey string) (*regexp.Regexp, error) {
	routingKey = strings.TrimSpace(routingKey)
	routingParts := strings.Split(routingKey, ".")

	for idx, routingPart := range routingParts {
		if routingPart == "*" {
			routingParts[idx] = "*"
		} else if routingPart == "#" {
			routingParts[idx] = "#"
		} else {
			routingParts[idx] = regexp.QuoteMeta(routingPart)
		}
	}

	routingKey = strings.Join(routingParts, "\\.")
	routingKey = strings.Replace(routingKey, "*", `([^\.]+)`, -1)

	for strings.HasPrefix(routingKey, "#\\.") {
		routingKey = strings.TrimPrefix(routingKey, "#\\.")
		if strings.HasPrefix(routingKey, "#\\.") {
			continue
		}
		routingKey = `(.*\.?)+` + routingKey
	}

	for strings.HasSuffix(routingKey, "\\.#") {
		routingKey = strings.TrimSuffix(routingKey, "\\.#")
		if strings.HasSuffix(routingKey, "\\.#") {
			continue
		}
		routingKey = routingKey + `(.*\.?)+`
	}
	routingKey = strings.Replace(routingKey, "\\.#\\.", `(.*\.?)+`, -1)
	routingKey = strings.Replace(routingKey, "#", `(.*\.?)+`, -1)
	pattern := "^" + routingKey + "$"

	return regexp.Compile(pattern)
}

// MatchDirect check is message can be routed from direct-exchange to queue
// with compare exchange and routing key
func (b *Binding) MatchDirect(exchange string, routingKey string) bool {
	return b.Exchange == exchange && b.RoutingKey == routingKey
}

// MatchFanout check is message can be routed from fanout-exchange to queue
// with compare only exchange
func (b *Binding) MatchFanout(exchange string) bool {
	return b.Exchange == exchange
}

// MatchTopic check is message can be routed from topic-exchange to queue
// with compare exchange and match topic-pattern with routing key
func (b *Binding) MatchTopic(exchange string, routingKey string) bool {
	return b.Exchange == exchange && b.regexp.MatchString(routingKey)
}

// MatchHeader checks whether the message can be routed on `b` for a
// header exchange type.
func (b *Binding) MatchHeader(exchange string, headers *amqp.Table) bool {
	if b.Exchange != exchange {
		return false
	}

	// If no arguments were declared by the exchange,
	// consider it is an always true route.
	if b.Arguments == nil {
		return true
	}

	if headers == nil {
		return false
	}

	bindingArgTable := *b.Arguments
	cliHeaders := *headers

	matchType := b.MatchType

	// Fallback solution for the x-match any case, and no other
	// argument in the table
	//
	// If no match is found in the loop, and arguments other than
	// x-match were specified, it should not return a positive
	// value in the end.
	hasNonXArgs := false

	for key, value := range bindingArgTable {
		// Any field starting with 'x-' shall be ignored
		if strings.HasPrefix(key, "x-") {
			continue
		}

		hasNonXArgs = true

		val, ok := cliHeaders[key]

		if !ok {
			if matchType == MatchAll {
				return false
			}
			continue
		}

		// @spec-note AMQP 0.9.1
		//
		// A message queue is bound to the exchange with a table of
		// arguments containing the headers to be matched for that
		// binding and optionally the values they should hold
		if value == nil {
			if matchType == MatchAny {
				return true
			}
			continue
		}

		if value == val {
			if matchType == MatchAny {
				return true
			}
			continue
		}

		if matchType == MatchAll {
			return false
		}
	}

	return matchType == MatchAll ||
		!hasNonXArgs && matchType == MatchAny
}

// GetExchange returns binding's exchange
func (b *Binding) GetExchange() string {
	return b.Exchange
}

// GetRoutingKey returns binding's routing key
func (b *Binding) GetRoutingKey() string {
	return b.RoutingKey
}

// GetQueue returns binding's queue
func (b *Binding) GetQueue() string {
	return b.Queue
}

// Equal returns is given binding equal to current
// with compare exchange, routing key and queue
func (b *Binding) Equal(bind *Binding) bool {
	return b.Exchange == bind.GetExchange() &&
		b.Queue == bind.GetQueue() &&
		b.RoutingKey == bind.GetRoutingKey() &&
		reflect.DeepEqual(b.Arguments, bind.Arguments)
}

// GetName generate binding name by concatenating its params
func (b *Binding) GetName() string {
	return strings.Join(
		[]string{b.Queue, b.Exchange, b.RoutingKey},
		"_",
	)
}

// Marshal returns raw representation of binding to store into storage
func (b *Binding) Marshal(protoVersion string) (data []byte, err error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	if err = amqp.WriteShortstr(buf, b.Queue); err != nil {
		return nil, err
	}
	if err = amqp.WriteShortstr(buf, b.Exchange); err != nil {
		return nil, err
	}
	if err = amqp.WriteShortstr(buf, b.RoutingKey); err != nil {
		return nil, err
	}
	// Since marshalling is used for storage only, we can
	// simplify the Marshal/Unmarshal of arguments by
	// writing them in Rabbit format, and reading them as such
	if err = amqp.WriteTable(buf, b.Arguments, protoVersion); err != nil {
		return nil, err
	}
	var topic byte
	if b.topic {
		topic = 1
	}
	if err = amqp.WriteOctet(buf, topic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal returns binding from storage raw bytes data
func (b *Binding) Unmarshal(data []byte, protoVersion string) (err error) {
	buf := bytes.NewReader(data)
	if b.Queue, err = amqp.ReadShortstr(buf); err != nil {
		return err
	}
	if b.Exchange, err = amqp.ReadShortstr(buf); err != nil {
		return err
	}
	if b.RoutingKey, err = amqp.ReadShortstr(buf); err != nil {
		return err
	}
	if b.Arguments, err = amqp.ReadTable(buf, protoVersion); err != nil {
		return err
	}
	var topic byte
	if topic, err = amqp.ReadOctet(buf); err != nil {
		return err
	}
	b.topic = topic == 1

	if b.topic {
		if b.regexp, err = buildRegexp(b.RoutingKey); err != nil {
			return err
		}
	}

	return
}
