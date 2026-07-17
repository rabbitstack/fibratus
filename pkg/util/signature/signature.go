/*
 * Copyright 2021-present by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package signature

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"expvar"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/golang/groupcache/singleflight"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
)

// requestQueueSize is the signature request input channel size
const requestQueueSize = 2048

var signatureAsyncRequestDrops = expvar.NewInt("signature.async.request.drops")

var signatureCiCount = expvar.NewInt("signature.ci.count")

var signatureCount = expvar.NewInt("signature.count")

var signatureCheckErrors = expvar.NewMap("signature.check.errors")

var signatureCacheHits = expvar.NewInt("signature.cache.hits")

var signatureCacheMisses = expvar.NewInt("signature.cache.misses")

var signatureEvictions = expvar.NewInt("signature.evictions")

var signatureInvalidations = expvar.NewMap("signature.invalidations")

var signatureCertParseErrors = expvar.NewMap("signature.cert.parse.errors")

// Key stores the attributes used for mapping the executable/DLL to its signature info.
type Key struct {
	// Path is the normalized NT device path of the executable/DLL file.
	Path string

	// ImageSize is the mapped image size from IMAGE_INFO. Free discriminator.
	// Distinguishes builds with identical timestamps (rare but possible
	// with reproducible builds or timestamp stripping).
	ImageSize uint64

	// CheckSum is PE optional header checksum. Included when non-zero.
	// Many debug/internal builds leave this as 0.
	CheckSum uint32

	// TimeDateStamp is the PE optional header attribute. Written by the
	// linker and changes on every rebuild.
	TimeDateStamp uint32
}

func (k Key) String() string {
	var b bytes.Buffer
	b.Grow(len(k.Path) + 16)

	b.WriteString(k.Path)
	b.Write(binary.LittleEndian.AppendUint32(nil, k.CheckSum))
	b.Write(binary.LittleEndian.AppendUint64(nil, k.ImageSize))
	b.Write(binary.LittleEndian.AppendUint32(nil, k.TimeDateStamp))

	return hex.EncodeToString(b.Bytes())
}

// IsDegenerate returns true when the key lacks enough entropy to be
// a reliable discriminator. In this case fall through to a synchronous
// inline check rather than risking a stale cache hit.
func (k Key) IsDegenerate() bool {
	return k.TimeDateStamp == 0 && k.CheckSum == 0
}

// MakeKey produces a new signature store key.
func MakeKey(path string, imageSize uint64, checksum, timeDateStamp uint32) Key {
	return Key{
		Path:          strings.ToLower(path),
		ImageSize:     imageSize,
		CheckSum:      checksum,
		TimeDateStamp: timeDateStamp,
	}
}

// Request contains the data necessary for querying the module signature info.
type Request struct {
	Key      Key
	Response chan<- *Signature // caller can optionally wait
}

// Signatures manages and caches DLL and executable signatures.
type Signatures struct {
	signatures map[Key]*Signature

	requests chan Request
	certs    chan Request

	mux    sync.RWMutex
	purger *time.Ticker

	group singleflight.Group

	stop chan struct{}
}

var sigs *Signatures
var once sync.Once

// sigTTL maximum time for the signature to remain in the
// internal store before it is purged.
var sigTTL = 10 * time.Minute

// GetSignatures creates a new signatures singleton.
func GetSignatures() *Signatures {
	once.Do(func() {
		sigs = newSignatures()
	})

	return sigs
}

func newSignatures() *Signatures {
	sigs = &Signatures{
		signatures: make(map[Key]*Signature, 512),
		purger:     time.NewTicker(time.Minute),
		requests:   make(chan Request, requestQueueSize),
		certs:      make(chan Request, requestQueueSize),
		stop:       make(chan struct{}),
	}

	workerCount := max(runtime.NumCPU()/2, 4)
	for range workerCount {
		go sigs.runWorker()
	}

	go sigs.runGC()

	return sigs
}

// Close shuts down the GC and worker goroutines. Call during graceful shutdown.
func (s *Signatures) Close() {
	s.purger.Stop()
	close(s.stop)
}

// DoRequest submits a signature check and blocks until the result is ready.
// Use this when the caller must make an allow/deny decision such as
// in the field accessors.
func (s *Signatures) DoRequest(key Key) *Signature {
	if key.IsDegenerate() {
		// degenerate keys bypass the cache entirely. We still want
		// LockOSThread on a worker, so route through the channel.
		// Fall through to the channel path below.
	} else {
		// hot path returns immediately if the signature is already resolved
		if sig := s.get(key); sig != nil {
			if sig.IsTrusted() && !sig.HasCertificate() {
				s.parseCertificate(sig)
			}
			return sig
		}
	}

	ch := make(chan *Signature, 1)
	select {
	case s.requests <- Request{Key: key, Response: ch}:
	default:
		// queue full: fall back to inline check rather than
		// dropping a decision that has a security consequence.
		signatureAsyncRequestDrops.Add(1)
		return s.getOrCheck(key)
	}
	r := <-ch
	return r
}

// DoRequestAsync submits a fire-and-forget signature check. The callback
// returns immediately and the result lands in the cache when ready.
// This is useful for the module-load hot path where we don't need
// to block the event.
func (s *Signatures) DoRequestAsync(key Key) {
	if s.contains(key) {
		return
	}
	select {
	case s.requests <- Request{Key: key}:
	default:
		// drop rather than block the event processing thread
		signatureAsyncRequestDrops.Add(1)
	}
}

// GetSignature retrieves the signature by the key. If
// the signature exists, its accessed timestamp is updated
// to prevent it being purged by the gc. If the signature is
// not found in the store, this method returns nil.
func (s *Signatures) GetSignature(key Key) *Signature {
	return s.get(key)
}

// RemoveSignature removes the signature from the store for the specified path.
func (s *Signatures) RemoveSignature(path string) {
	var stale []Key
	p := strings.ToLower(path)

	s.mux.RLock()
	for k := range s.signatures {
		if k.Path == p {
			stale = append(stale, k)
		}
	}
	s.mux.RUnlock()

	if len(stale) == 0 {
		return
	}

	s.mux.Lock()
	for _, k := range stale {
		delete(s.signatures, k)
		signatureCount.Add(-1)
		signatureInvalidations.Add(k.Path, 1)
	}
	s.mux.Unlock()
}

// PutSignature puts the signature where the signature type and level are
// typically attributed to trusted signatures. For this reason, we can skip
// WinTrust verification and directly proceed to certificate parsing.
func (s *Signatures) PutSignature(key Key, sigType Type, sigLevel Level) {
	if s.contains(key) {
		return
	}

	s.mux.Lock()
	s.signatures[key] = newSignature(key.Path, sigType, sigLevel)
	s.mux.Unlock()
	signatureCount.Add(1)
	signatureCiCount.Add(1)

	select {
	case s.certs <- Request{Key: key}:
	default:
	}
}

// get is the shared read path. RLock allows many concurrent readers.
// The keepalive write is atomic so we never need to upgrade to a write lock.
func (s *Signatures) get(key Key) *Signature {
	s.mux.RLock()
	sig := s.signatures[key]
	s.mux.RUnlock()
	if sig != nil {
		sig.keepalive() // atomic write, no lock needed
		signatureCacheHits.Add(1)
	}
	return sig
}

// contains returns true if the signature with the given key exists in the store.
// If the signature doesn't exist, this method returns false.
func (s *Signatures) contains(key Key) bool {
	return s.get(key) != nil
}

func (s *Signatures) getOrCheck(key Key) *Signature {
	if sig := s.get(key); sig != nil {
		return sig
	}

	// singleflight.Do ensures that if N goroutines miss the same key
	// concurrently, only one of them does the PE/catalog work, while the
	// rest block and share the result. This is critical during process
	// startup when many threads load the same DLL simultaneously
	v, err := s.group.Do(key.String(), func() (any, error) {
		sig := newUncheckedSignature(key.Path)
		if err := sig.check(); err != nil {
			return sig, err
		}
		return sig, nil
	})

	if err != nil {
		signatureCheckErrors.Add(err.Error(), 1)
	}

	// put the signature in the store
	s.mux.Lock()
	sign := v.(*Signature)
	s.signatures[key] = sign
	s.mux.Unlock()
	signatureCount.Add(1)
	signatureCacheMisses.Add(1)

	return sign
}

func (s *Signatures) runWorker() {
	// pin this goroutine to its OS thread for the lifetime of the worker.
	// WinVerifyTrust has COM STA thread affinity and all calls must happen
	// on a thread where CoInitializeEx has been called.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		select {
		case req := <-s.requests:
			s.processRequest(req)
		case req := <-s.certs:
			sig := s.get(req.Key)
			if sig != nil {
				continue
			}
			s.parseCertificate(sig)
		case <-s.stop:
			return
		}
	}
}

func (s *Signatures) processRequest(req Request) {
	sign := s.getOrCheck(req.Key)
	if req.Response != nil {
		req.Response <- sign
	}
}

// gc removes entries that have not been accessed within sigTTL.
// It reads the accessed timestamp via an atomic load, so it does not
// need to hold the write lock while computing ages.
func (s *Signatures) runGC() {
	for {
		select {
		case <-s.purger.C:
			s.gcSignatures()
		case <-s.stop:
			return
		}
	}
}

func (s *Signatures) gcSignatures() {
	now := time.Now()

	// collect stale keys under a read lock to minimize write-lock hold time
	s.mux.RLock()
	var stale []Key
	for key, sig := range s.signatures {
		if now.Sub(sig.lastAccessed()) > sigTTL {
			stale = append(stale, key)
		}
	}
	s.mux.RUnlock()

	if len(stale) == 0 {
		return
	}

	s.mux.Lock()
	for _, key := range stale {
		sig := s.signatures[key]
		// re-check under the write lock: the entry may have been
		// refreshed between the RUnlock above and this Lock
		if sig != nil && now.Sub(sig.lastAccessed()) > sigTTL {
			log.Debugf("evicting signature for %s", sig.Path)
			delete(s.signatures, key)
			signatureCount.Add(-1)
			signatureEvictions.Add(1)
		}
	}
	s.mux.Unlock()
}

func (s *Signatures) parseCertificate(sig *Signature) {
	cert, err := sig.parseCertificate(false)
	if err != nil {
		signatureCertParseErrors.Add(err.Error(), 1)
		return
	}
	sig.setCert(cert)
}

// check determines if the executable image or DLL is signed and trusted.
// It first parses the PE security directory to look for the signature
// information. If the certificate is not embedded inside the PE object
// then this method will try to locate the hash in the catalog file.
// If the signature is not present, this function returns ErrNoSignature
// error. On the contrary, the signature chain trust is verified and
// the catalog certificates are parsed.
func (s *Signature) check() error {
	if s == nil {
		return ErrNilSignature
	}

	// check if the signature is embedded in PE
	f, err := pe.ParseFile(s.Path, pe.WithSecurity())
	if err != nil {
		return err
	}

	if f.IsSigned() {
		s.setExists()
		s.setType(TypeEmbedded)
		s.setCert(f.Cert)
		if !sys.IsWintrustFound() {
			return ErrWintrustUnavailable
		}
		return s.verifyFile()
	}

	if !sys.IsWintrustFound() {
		return ErrWintrustUnavailable
	}

	// maybe the signature is in the catalog?
	catalog := sys.NewCatalog()
	if err := catalog.Open(s.Path); err != nil {
		return ErrNoSignature
	}
	defer catalog.Close()

	if !catalog.IsCatalogSigned() {
		return ErrNoSignature
	}
	s.setExists()
	s.setType(TypeCatalogCached)

	if err := s.verifyCatalog(catalog); err != nil {
		return err
	}
	cert, err := catalog.ParseCertificate()
	if err != nil {
		signatureCertParseErrors.Add(err.Error(), 1)
		return err
	}
	s.setCert(cert)

	return nil
}
