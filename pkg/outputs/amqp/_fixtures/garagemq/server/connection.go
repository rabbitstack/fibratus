package server

import (
	"bufio"
	"bytes"
	"context"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp/_fixtures/garagemq/qos"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// connection status list
const (
	ConnStart = iota
	ConnStartOK
	ConnSecure
	ConnSecureOK
	ConnTune
	ConnTuneOK
	ConnOpen
	ConnOpenOK
	ConnCloseOK
	ConnClosed
)

// From https://github.com/rabbitmq/rabbitmq-common/blob/master/src/rabbit_writer.erl
// When the amount of protocol method data buffered exceeds
// this threshold, a socket flush is performed.
//
// This magic number is the tcp-over-ethernet MSS (1460) minus the
// minimum size of a AMQP 0-9-1 basic.deliver method frame (24) plus basic
// content header (22). The idea is that we want to flush just before
// exceeding the MSS.
const flushThreshold = 1414

// Connection represents AMQP-connection
type Connection struct {
	id               uint64
	server           *Server
	netConn          *net.TCPConn
	logger           *log.Entry
	channelsLock     sync.RWMutex
	channels         map[uint16]*Channel
	outgoing         chan *amqp.Frame
	clientProperties *amqp.Table
	maxChannels      uint16
	maxFrameSize     uint32
	statusLock       sync.RWMutex
	status           int
	qos              *qos.AmqpQos
	virtualHost      *VirtualHost
	vhostName        string
	closeCh          chan bool
	userName         string

	wg        *sync.WaitGroup
	ctx       context.Context
	cancelCtx context.CancelFunc

	heartbeatInterval uint16
	heartbeatTimeout  uint16
	heartbeatTimer    *time.Ticker

	lastOutgoingTS chan time.Time
}

// NewConnection returns new instance of amqp Connection
func NewConnection(server *Server, netConn *net.TCPConn) (connection *Connection) {
	connection = &Connection{
		id:                atomic.AddUint64(&server.connSeq, 1),
		server:            server,
		netConn:           netConn,
		channels:          make(map[uint16]*Channel),
		outgoing:          make(chan *amqp.Frame, 128),
		maxChannels:       server.config.Connection.ChannelsMax,
		maxFrameSize:      server.config.Connection.FrameMaxSize,
		qos:               qos.NewAmqpQos(0, 0),
		closeCh:           make(chan bool, 2),
		wg:                &sync.WaitGroup{},
		lastOutgoingTS:    make(chan time.Time),
		heartbeatInterval: 10,
	}

	connection.logger = log.WithFields(log.Fields{
		"connectionId": connection.id,
	})

	return
}

func (conn *Connection) close() {
	conn.statusLock.Lock()
	if conn.status == ConnClosed {
		conn.statusLock.Unlock()
		return
	}

	if conn.heartbeatTimer != nil {
		conn.heartbeatTimer.Stop()
	}

	conn.status = ConnClosed
	conn.statusLock.Unlock()

	// @todo should we chech for errors here? And what should we do if error occur
	_ = conn.netConn.Close()

	if conn.cancelCtx != nil {
		conn.cancelCtx()
	}

	conn.wg.Wait()

	// channel0 should we be closed at the end
	channelIds := make([]int, 0)
	conn.channelsLock.Lock()
	for chID := range conn.channels {
		channelIds = append(channelIds, int(chID))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(channelIds)))
	for _, chID := range channelIds {
		channel := conn.channels[uint16(chID)]
		channel.delete()
		delete(conn.channels, uint16(chID))
	}
	conn.channelsLock.Unlock()
	conn.clearQueues()

	conn.logger.WithFields(log.Fields{
		"vhost": conn.vhostName,
		"from":  conn.netConn.RemoteAddr(),
	}).Info("Connection closed")
	conn.server.removeConnection(conn.id)

	conn.closeCh <- true
}

func (conn *Connection) getChannel(id uint16) *Channel {
	conn.channelsLock.Lock()
	channel := conn.channels[id]
	conn.channelsLock.Unlock()
	return channel
}

func (conn *Connection) safeClose(wg *sync.WaitGroup) {
	defer wg.Done()

	ch := conn.getChannel(0)
	if ch == nil {
		return
	}
	ch.SendMethod(&amqp.ConnectionClose{
		ReplyCode: amqp.ConnectionForced,
		ReplyText: "Server shutdown",
		ClassID:   0,
		MethodID:  0,
	})

	// let clients proper handle connection closing in 10 sec
	timeOut := time.After(10 * time.Second)

	select {
	case <-timeOut:
		conn.close()
		return
	case <-conn.closeCh:
		return
	}
}

func (conn *Connection) clearQueues() {
	virtualHost := conn.GetVirtualHost()
	if virtualHost == nil {
		// it is possible when conn close before open, for example login failure
		return
	}
	for _, queue := range virtualHost.GetQueues() {
		if queue.IsExclusive() && queue.ConnID() == conn.id {
			virtualHost.DeleteQueue(queue.GetName(), false, false)
		}
	}
}

func (conn *Connection) handleConnection() {
	buf := make([]byte, 8)
	_, err := conn.netConn.Read(buf)
	if err != nil {
		conn.logger.WithError(err).WithFields(log.Fields{
			"read buffer": buf,
		}).Error("Error on read protocol header")
		conn.close()
		return
	}

	// @spec-note
	// If the server cannot support the protocol specified in the protocol header,
	// it MUST respond with a valid protocol header and then close the socket connection.
	// The client MUST start a new connection by sending a protocol header
	if !bytes.Equal(buf, amqp.AmqpHeader) {
		conn.logger.WithFields(log.Fields{
			"given":     buf,
			"supported": amqp.AmqpHeader,
		}).Warn("Unsupported protocol")
		_, _ = conn.netConn.Write(amqp.AmqpHeader)
		conn.close()
		return
	}

	conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())

	channel := NewChannel(0, conn)
	conn.channelsLock.Lock()
	conn.channels[channel.id] = channel
	conn.channelsLock.Unlock()

	channel.start()
	conn.wg.Add(1)
	go conn.handleOutgoing()
	conn.wg.Add(1)
	go conn.handleIncoming()
}

func (conn *Connection) handleOutgoing() {
	defer func() {
		close(conn.lastOutgoingTS)
		conn.wg.Done()
		conn.close()
	}()

	var err error
	buffer := bufio.NewWriterSize(conn.netConn, 128<<10)
	for {
		select {
		case <-conn.ctx.Done():
			return
		case frame := <-conn.outgoing:
			if frame == nil {
				return
			}

			if err = amqp.WriteFrame(buffer, frame); err != nil && !conn.isClosedError(err) {
				conn.logger.WithError(err).Warn("writing frame")
				return
			}

			if frame.CloseAfter {
				if err = buffer.Flush(); err != nil && !conn.isClosedError(err) {
					conn.logger.WithError(err).Warn("writing frame")
				}
				return
			}

			if frame.Sync {
				if err = buffer.Flush(); err != nil && !conn.isClosedError(err) {
					conn.logger.WithError(err).Warn("writing frame")
					return
				}
			} else {
				if err = conn.mayBeFlushBuffer(buffer); err != nil && !conn.isClosedError(err) {
					conn.logger.WithError(err).Warn("writing frame")
					return
				}
			}

			select {
			case conn.lastOutgoingTS <- time.Now():
			default:
			}
		}
	}
}

func (conn *Connection) mayBeFlushBuffer(buffer *bufio.Writer) (err error) {
	if buffer.Buffered() >= flushThreshold {
		if err = buffer.Flush(); err != nil {
			return err
		}
	}

	if len(conn.outgoing) == 0 {
		// outgoing channel is buffered and we can check is here more messages for store into buffer
		// if nothing to store into buffer - we flush
		if err = buffer.Flush(); err != nil {
			return err
		}
	}
	return
}

func (conn *Connection) handleIncoming() {
	defer func() {
		conn.wg.Done()
		conn.close()
	}()

	buffer := bufio.NewReaderSize(conn.netConn, 128<<10)

	for {
		// TODO
		// @spec-note
		// After sending connection.close , any received methods except Close and Close­OK MUST be discarded.
		// The response to receiving a Close after sending Close must be to send Close­Ok.
		frame, err := amqp.ReadFrame(buffer)
		if err != nil {
			if err.Error() != "EOF" && !conn.isClosedError(err) {
				conn.logger.WithError(err).Warn("reading frame")
			}
			return
		}

		if conn.status < ConnOpen && frame.ChannelID != 0 {
			conn.logger.WithError(err).Error("Frame not allowed for unopened connection")
			return
		}

		conn.channelsLock.RLock()
		channel, ok := conn.channels[frame.ChannelID]
		conn.channelsLock.RUnlock()

		if !ok {
			channel = NewChannel(frame.ChannelID, conn)

			conn.channelsLock.Lock()
			conn.channels[frame.ChannelID] = channel
			conn.channelsLock.Unlock()

			channel.start()
		}

		if conn.heartbeatTimeout > 0 {
			if err = conn.netConn.SetReadDeadline(time.Now().Add(time.Duration(conn.heartbeatTimeout) * time.Second)); err != nil {
				conn.logger.WithError(err).Warn("reading frame")
				return
			}
		}

		if frame.Type == amqp.FrameHeartbeat && frame.ChannelID != 0 {
			return
		}

		select {
		case <-conn.ctx.Done():
			close(channel.incoming)
			return
		case channel.incoming <- frame:
		}
	}
}

func (conn *Connection) heartBeater() {
	interval := time.Duration(conn.heartbeatInterval) * time.Second
	conn.heartbeatTimer = time.NewTicker(interval)

	var (
		ok     bool
		lastTs = time.Now()
	)

	heartbeatFrame := &amqp.Frame{Type: byte(amqp.FrameHeartbeat), ChannelID: 0, Payload: []byte{}, CloseAfter: false, Sync: true}

	go func() {
		for {
			select {
			case lastTs, ok = <-conn.lastOutgoingTS:
				if !ok {
					return
				}
			}
		}
	}()

	for tickTime := range conn.heartbeatTimer.C {
		if tickTime.Sub(lastTs) >= interval-time.Second {
			conn.outgoing <- heartbeatFrame
		}
	}
}

func (conn *Connection) isClosedError(err error) bool {
	// See: https://github.com/golang/go/issues/4373
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

func (conn *Connection) GetVirtualHost() *VirtualHost {
	return conn.virtualHost
}

func (conn *Connection) GetRemoteAddr() net.Addr {
	return conn.netConn.RemoteAddr()
}

func (conn *Connection) GetChannels() map[uint16]*Channel {
	return conn.channels
}

func (conn *Connection) GetID() uint64 {
	return conn.id
}

func (conn *Connection) GetUsername() string {
	return conn.userName
}
