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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	debugpe "debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"go.mozilla.org/pkcs7"
)

var (
	testNotBefore = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	testNotAfter  = time.Date(2034, 6, 7, 8, 9, 10, 0, time.UTC)
)

type identity struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newIdentity creates a certificate with the given name and serial. If parent
// is nil, the certificate is self-signed.
func newIdentity(t testing.TB, name pkix.Name, serial *big.Int, parent *identity) *identity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		NotBefore:             testNotBefore,
		NotAfter:              testNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  parent == nil,
	}
	issuer, issuerKey := tmpl, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &identity{cert: cert, key: key}
}

func fullName(org, cn string) pkix.Name {
	return pkix.Name{
		Country:      []string{"US"},
		Province:     []string{"WA"},
		Locality:     []string{"Redmond"},
		Organization: []string{org},
		CommonName:   cn,
	}
}

// signBlob produces the DER PKCS#7 SignedData signed by the signer. Any
// extra certificates are placed in the certificate set before the signer's.
func signBlob(t testing.TB, signer *identity, extra ...*x509.Certificate) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte("authenticode"))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	for _, c := range extra {
		sd.AddCertificate(c)
	}
	if err := sd.AddSigner(signer.cert, signer.key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	b, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const ntOffset = 0x80 // where the NT headers are placed in the synthetic images

type segment struct {
	off  int64
	data []byte
}

// image is a (possibly huge) file whose content is zero except for the
// segments. It implements io.ReaderAt and counts the I/O made against it.
type image struct {
	segs  []segment
	size  int64
	reads atomic.Int64
	read  atomic.Int64
}

func (im *image) ReadAt(p []byte, off int64) (int, error) {
	im.reads.Add(1)
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= im.size {
		return 0, io.EOF
	}
	n := int64(len(p))
	var err error
	if rem := im.size - off; n > rem {
		n, err = rem, io.EOF
	}
	clear(p[:n])
	for _, s := range im.segs {
		end := s.off + int64(len(s.data))
		if end <= off || s.off >= off+n {
			continue
		}
		from, to := max(s.off, off), min(end, off+n)
		copy(p[from-off:to-off], s.data[from-s.off:to-s.off])
	}
	im.read.Add(n)
	return int(n), err
}

// bytes materializes the whole image in memory.
func (im *image) bytes() []byte {
	buf := make([]byte, im.size)
	_, _ = im.ReadAt(buf, 0)
	im.reads.Store(0)
	im.read.Store(0)
	return buf
}

// writeTo materializes the image on disk. The file is sparse where the
// file system supports it.
func (im *image) writeTo(t testing.TB, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(im.size); err != nil {
		t.Fatal(err)
	}
	for _, s := range im.segs {
		if _, err := f.WriteAt(s.data, s.off); err != nil {
			t.Fatal(err)
		}
	}
}

const noDirectories = -1 // spec.numDirs value that requests zero data directories

// spec describes the synthetic image. Zero values produce a well-formed
// PE32+ image.
type spec struct {
	pe32 bool // 32-bit optional header layout

	numDirs     int    // NumberOfRvaAndSizes; 0 means 16, noDirectories means 0
	optSize     uint16 // SizeOfOptionalHeader; 0 means natural size
	optMagic    uint16 // optional header magic; 0 means the one for the layout
	dosMagic    string // overrides "MZ"
	ntSig       uint32 // overrides "PE\0\0"
	lfanewField uint32 // e_lfanew value; 0 means ntOffset

	table     []byte // raw certificate table, the content of the security directory
	padTo     int64  // the table is placed at or after this file offset
	dirOffset uint32 // overrides the directory address
	dirSize   uint32 // overrides the directory size
	size      int64  // minimum logical file size
}

func buildImage(s spec) *image {
	dirsOff, magic, machine := pe32PlusDataDirsOffset, uint16(optionalMagicPE32Plus), uint16(0x8664)
	if s.pe32 {
		dirsOff, magic, machine = pe32DataDirsOffset, optionalMagicPE32, 0x14c
	}
	if s.optMagic != 0 {
		magic = s.optMagic
	}
	natural := dirsOff + 16*dataDirEntrySize
	optSize := s.optSize
	if optSize == 0 {
		optSize = uint16(natural)
	}
	ndirs := uint32(16)
	switch {
	case s.numDirs > 0:
		ndirs = uint32(s.numDirs)
	case s.numDirs < 0:
		ndirs = 0
	}

	head := make([]byte, ntOffset+4+fileHeaderSize+natural)
	copy(head, "MZ")
	if s.dosMagic != "" {
		copy(head, s.dosMagic)
	}
	lfanew := s.lfanewField
	if lfanew == 0 {
		lfanew = ntOffset
	}
	binary.LittleEndian.PutUint32(head[dosNTHeaderOffset:], lfanew)

	sig := s.ntSig
	if sig == 0 {
		sig = ntSignature
	}
	binary.LittleEndian.PutUint32(head[ntOffset:], sig)
	fh := head[ntOffset+4:]
	binary.LittleEndian.PutUint16(fh, machine)
	binary.LittleEndian.PutUint16(fh[fileHeaderOptSizeOff:], optSize)
	opt := fh[fileHeaderSize:]
	binary.LittleEndian.PutUint16(opt, magic)
	binary.LittleEndian.PutUint32(opt[dirsOff-4:], ndirs)

	im := &image{segs: []segment{{0, head}}}
	end := int64(len(head))

	if len(s.table) > 0 {
		off := max(int64(len(head)), s.padTo)
		off = (off + 7) &^ 7
		im.segs = append(im.segs, segment{off, s.table})
		end = off + int64(len(s.table))

		dirOffset, dirSize := uint32(off), uint32(len(s.table))
		if s.dirOffset != 0 {
			dirOffset = s.dirOffset
		}
		if s.dirSize != 0 {
			dirSize = s.dirSize
		}
		entry := opt[dirsOff+dataDirSecurity*dataDirEntrySize:]
		binary.LittleEndian.PutUint32(entry, dirOffset)
		binary.LittleEndian.PutUint32(entry[4:], dirSize)
	}
	im.size = max(end, s.size)

	return im
}

// rawWinCert builds a WIN_CERTIFICATE with an arbitrary dwLength, padded to 8 bytes
// as the linker does.
func rawWinCert(length uint32, certType uint16, body []byte) []byte {
	b := make([]byte, winCertHeaderSize+len(body))
	binary.LittleEndian.PutUint32(b, length)
	binary.LittleEndian.PutUint16(b[4:], 0x0200) // WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(b[6:], certType)
	copy(b[winCertHeaderSize:], body)
	if pad := (8 - len(b)%8) % 8; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

func winCert(blob []byte) []byte {
	return rawWinCert(uint32(winCertHeaderSize+len(blob)), winCertTypePKCSSignedData, blob)
}

func parse(im *image) (bool, *sys.Cert, error) {
	return parseSecurityDirectoryAt(im, im.size)
}

func wantCert(t *testing.T, got *sys.Cert, id *identity, issuer, subject string) {
	t.Helper()
	if got == nil {
		t.Fatal("expected a certificate, got nil")
	}
	if want := hex.EncodeToString(id.cert.SerialNumber.Bytes()); got.SerialNumber != want {
		t.Errorf("serial: got %q, want %q", got.SerialNumber, want)
	}
	if got.Issuer != issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, issuer)
	}
	if got.Subject != subject {
		t.Errorf("subject: got %q, want %q", got.Subject, subject)
	}
	if !got.NotBefore.Equal(testNotBefore) || !got.NotAfter.Equal(testNotAfter) {
		t.Errorf("validity: got [%s, %s], want [%s, %s]", got.NotBefore, got.NotAfter, testNotBefore, testNotAfter)
	}
}

func sameCert(a, b *sys.Cert) bool {
	return a.Issuer == b.Issuer && a.Subject == b.Subject && a.SerialNumber == b.SerialNumber &&
		a.NotBefore.Equal(b.NotBefore) && a.NotAfter.Equal(b.NotAfter)
}

func TestParseSecurityDirectoryUnsigned(t *testing.T) {
	tests := []struct {
		name string
		spec spec
	}{
		{"no certificate table", spec{}},
		{"no certificate table PE32", spec{pe32: true}},
		// the security entry is present but the loader only honours the first
		// NumberOfRvaAndSizes entries
		{"security entry beyond NumberOfRvaAndSizes", spec{table: winCert([]byte{1}), numDirs: 4}},
		{"no data directories", spec{table: winCert([]byte{1}), numDirs: noDirectories}},
		// the optional header can't hold the security entry
		{"optional header too small for security entry", spec{table: winCert([]byte{1}), optSize: pe32PlusDataDirsOffset + 8}},
		{"optional header only holds the magic", spec{table: winCert([]byte{1}), optSize: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, cert, err := parse(buildImage(tt.spec))
			if err != nil || signed || cert != nil {
				t.Fatalf("got (%t, %v, %v), want (false, nil, nil)", signed, cert, err)
			}
		})
	}
}

func TestParseSecurityDirectorySigned(t *testing.T) {
	signer := newIdentity(t, fullName("Fibratus Test Corp", "Fibratus Test Signer"), big.NewInt(0x7a7a7a7a7a7a7a7a), nil)
	blob := signBlob(t, signer)

	for _, layout := range []struct {
		name string
		pe32 bool
	}{{"PE32+", false}, {"PE32", true}} {
		t.Run(layout.name, func(t *testing.T) {
			signed, cert, err := parse(buildImage(spec{pe32: layout.pe32, table: winCert(blob)}))
			if err != nil || !signed {
				t.Fatalf("got (%t, _, %v), want (true, _, nil)", signed, err)
			}
			wantCert(t, cert, signer,
				"US, WA, Redmond, Fibratus Test Signer",
				"US, WA, Redmond, Fibratus Test Corp, Fibratus Test Signer")
		})
	}
}

// The certificate set isn't ordered with the signer first. The first
// certificate in the set is the issuing CA here, and it must not be reported.
func TestParseSecurityDirectoryPicksSignerNotFirstCertificate(t *testing.T) {
	ca := newIdentity(t, fullName("Fibratus Test CA Org", "Fibratus Test CA"), big.NewInt(1), nil)
	leaf := newIdentity(t, fullName("Fibratus Test Corp", "Fibratus Test Leaf"), big.NewInt(2), ca)
	blob := signBlob(t, leaf, ca.cert)

	signed, cert, err := parse(buildImage(spec{table: winCert(blob)}))
	if err != nil || !signed {
		t.Fatalf("got (%t, _, %v), want (true, _, nil)", signed, err)
	}
	wantCert(t, cert, leaf,
		"US, WA, Redmond, Fibratus Test CA",
		"US, WA, Redmond, Fibratus Test Corp, Fibratus Test Leaf")
}

// Serial numbers are only unique per issuer. Two certificates in the set
// share the serial, and the signer is the one issued by the second CA.
func TestParseSecurityDirectorySameSerialDifferentIssuer(t *testing.T) {
	ca1 := newIdentity(t, fullName("CA One Org", "CA One"), big.NewInt(100), nil)
	ca2 := newIdentity(t, fullName("CA Two Org", "CA Two"), big.NewInt(200), nil)
	impostor := newIdentity(t, fullName("Impostor Corp", "Impostor"), big.NewInt(5), ca1)
	signer := newIdentity(t, fullName("Real Corp", "Real Signer"), big.NewInt(5), ca2)

	blob := signBlob(t, signer, impostor.cert)

	signed, cert, err := parse(buildImage(spec{table: winCert(blob)}))
	if err != nil || !signed {
		t.Fatalf("got (%t, _, %v), want (true, _, nil)", signed, err)
	}
	wantCert(t, cert, signer, "US, WA, Redmond, CA Two", "US, WA, Redmond, Real Corp, Real Signer")
}

// The strings are formatted as before the rewrite: a missing country leaves
// a leading separator, and the issuer doesn't include the organization.
func TestParseSecurityDirectoryCertFormatIsPreserved(t *testing.T) {
	signer := newIdentity(t, pkix.Name{Organization: []string{"Org"}, CommonName: "CN"}, big.NewInt(9), nil)

	_, cert, err := parse(buildImage(spec{table: winCert(signBlob(t, signer))}))
	if err != nil {
		t.Fatal(err)
	}
	wantCert(t, cert, signer, ", CN", ", Org, CN")
}

func TestParseSecurityDirectoryLargeImage(t *testing.T) {
	signer := newIdentity(t, fullName("Big Corp", "Big Signer"), big.NewInt(77), nil)
	table := winCert(signBlob(t, signer))

	for _, size := range []int64{1 << 20, 8 << 20, 9 << 20, 64 << 20, 300 << 20} {
		t.Run(fmt.Sprintf("%dMB", size>>20), func(t *testing.T) {
			im := buildImage(spec{table: table, padTo: size})
			signed, cert, err := parse(im)
			if err != nil || !signed {
				t.Fatalf("got (%t, _, %v), want (true, _, nil)", signed, err)
			}
			wantCert(t, cert, signer, "US, WA, Redmond, Big Signer", "US, WA, Redmond, Big Corp, Big Signer")

			if limit := int64(len(table)) + 1024; im.read.Load() > limit {
				t.Errorf("read %d bytes from a %d byte image, want at most %d", im.read.Load(), im.size, limit)
			}
			if im.reads.Load() > 12 {
				t.Errorf("made %d reads, want a handful", im.reads.Load())
			}
		})
	}
}

func TestParseSecurityDirectoryFile(t *testing.T) {
	signer := newIdentity(t, fullName("File Corp", "File Signer"), big.NewInt(88), nil)
	table := winCert(signBlob(t, signer))

	t.Run("signed file larger than 8MB", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "big.dll")
		buildImage(spec{table: table, padTo: 12 << 20}).writeTo(t, path)

		signed, cert, err := parseSecurityDirectory(path)
		if err != nil || !signed {
			t.Fatalf("got (%t, _, %v), want (true, _, nil)", signed, err)
		}
		wantCert(t, cert, signer, "US, WA, Redmond, File Signer", "US, WA, Redmond, File Corp, File Signer")
	})

	t.Run("unsigned file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "unsigned.dll")
		buildImage(spec{}).writeTo(t, path)

		signed, cert, err := parseSecurityDirectory(path)
		if err != nil || signed || cert != nil {
			t.Fatalf("got (%t, %v, %v), want (false, nil, nil)", signed, cert, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		signed, cert, err := parseSecurityDirectory(filepath.Join(t.TempDir(), "nope.dll"))
		if !errors.Is(err, os.ErrNotExist) || signed || cert != nil {
			t.Fatalf("got (%t, %v, %v), want (false, nil, ErrNotExist)", signed, cert, err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.dll")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		signed, cert, err := parseSecurityDirectory(path)
		if !errors.Is(err, errNotPE) || signed || cert != nil {
			t.Fatalf("got (%t, %v, %v), want (false, nil, errNotPE)", signed, cert, err)
		}
	})

}

func TestParseSecurityDirectoryMalformed(t *testing.T) {
	signer := newIdentity(t, fullName("Corp", "Signer"), big.NewInt(3), nil)
	blob := signBlob(t, signer)
	good := winCert(blob)

	tests := []struct {
		name       string
		img        *image
		wantSigned bool   // the image has a certificate table
		wantErr    string // substring of the error
		wantNotPE  bool
	}{
		// not a usable PE: nothing can be said about a signature
		{name: "10 bytes", img: &image{segs: []segment{{0, []byte("MZ12345678")}}, size: 10}, wantErr: "reading DOS header", wantNotPE: true},
		{name: "bad DOS magic", img: buildImage(spec{dosMagic: "ZM"}), wantErr: "bad DOS signature", wantNotPE: true},
		{name: "e_lfanew beyond EOF", img: buildImage(spec{lfanewField: 0x7fffffff}), wantErr: "reading NT headers", wantNotPE: true},
		{name: "bad NT signature", img: buildImage(spec{ntSig: 0x00004551}), wantErr: "bad NT signature", wantNotPE: true},
		{name: "no optional header", img: buildImage(spec{optSize: 1}), wantErr: "no optional header", wantNotPE: true},
		{name: "unknown optional magic", img: buildImage(spec{optMagic: 0x107}), wantErr: "unknown optional header magic", wantNotPE: true},

		// a certificate table exists, but its content is unusable. The image
		// is still signed, and the caller has to verify it as such
		{name: "directory beyond EOF", img: buildImage(spec{table: good, dirOffset: 0x10000000}), wantSigned: true, wantErr: "exceeds file size"},
		{name: "directory size beyond EOF", img: buildImage(spec{table: good, dirSize: 0x10000000}), wantSigned: true, wantErr: "exceeds file size"},
		{name: "directory smaller than header", img: buildImage(spec{table: good, dirSize: 4}), wantSigned: true, wantErr: "too small"},
		{name: "unsupported certificate type", img: buildImage(spec{table: rawWinCert(uint32(winCertHeaderSize+len(blob)), 0x0001, blob)}), wantSigned: true, wantErr: "unsupported certificate type"},
		{name: "length larger than directory", img: buildImage(spec{table: rawWinCert(uint32(len(good))+64, winCertTypePKCSSignedData, blob)}), wantSigned: true, wantErr: "invalid certificate length"},
		{name: "length smaller than header", img: buildImage(spec{table: rawWinCert(4, winCertTypePKCSSignedData, blob)}), wantSigned: true, wantErr: "invalid certificate length"},
		{name: "blob too large", img: buildImage(spec{
			table:   rawWinCert(winCertHeaderSize+maxCertBlobSize+1, winCertTypePKCSSignedData, nil),
			dirSize: winCertHeaderSize + maxCertBlobSize + 1,
			size:    16 << 20,
		}), wantSigned: true, wantErr: "too large"},
		{name: "empty blob", img: buildImage(spec{table: rawWinCert(winCertHeaderSize, winCertTypePKCSSignedData, nil)}), wantSigned: true, wantErr: "parse PKCS#7"},
		{name: "garbage blob", img: buildImage(spec{table: winCert(bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 64))}), wantSigned: true, wantErr: "parse PKCS#7"},
		{name: "truncated blob", img: buildImage(spec{table: winCert(blob[:len(blob)/2])}), wantSigned: true, wantErr: "parse PKCS#7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, cert, err := parse(tt.img)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %v, want it to contain %q", err, tt.wantErr)
			}
			if signed != tt.wantSigned {
				t.Errorf("signed: got %t, want %t", signed, tt.wantSigned)
			}
			if cert != nil {
				t.Errorf("certificate: got %+v, want nil", cert)
			}
			if errors.Is(err, errNotPE) != tt.wantNotPE {
				t.Errorf("errors.Is(err, errNotPE): got %t, want %t", !tt.wantNotPE, tt.wantNotPE)
			}
		})
	}
}

func TestParseSecurityDirectorySignatureWithoutSigners(t *testing.T) {
	sd, err := pkcs7.NewSignedData([]byte("authenticode"))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}

	signed, cert, err := parse(buildImage(spec{table: winCert(blob)}))
	if !signed || cert != nil || err == nil || !strings.Contains(err.Error(), "no signers") {
		t.Fatalf("got (%t, %v, %v), want (true, nil, \"no signers\")", signed, cert, err)
	}
}

// The signer's issuer and serial identify a certificate that isn't in the set.
func TestParseSecurityDirectorySignerCertificateMissing(t *testing.T) {
	signer := newIdentity(t, fullName("Corp", "Signer"), big.NewInt(0x5b5b5b5b5b5b5b5b), nil)
	blob := signBlob(t, signer)

	// The serial appears twice: in the certificate, and in the SignerInfo that
	// follows the certificate set. Corrupt the last occurrence only.
	needle := bytes.Repeat([]byte{0x5b}, 8)
	if bytes.Count(blob, needle) != 2 {
		t.Fatalf("expected the serial to occur twice, got %d", bytes.Count(blob, needle))
	}
	i := bytes.LastIndex(blob, needle)
	copy(blob[i:], bytes.Repeat([]byte{0x5c}, 8))

	signed, cert, err := parse(buildImage(spec{table: winCert(blob)}))
	if !signed || cert != nil || err == nil || !strings.Contains(err.Error(), "signer certificate not found") {
		t.Fatalf("got (%t, %v, %v), want (true, nil, \"signer certificate not found\")", signed, cert, err)
	}
}

func TestParseSecurityDirectoryReaderErrors(t *testing.T) {
	signer := newIdentity(t, fullName("Corp", "Signer"), big.NewInt(4), nil)
	blob := signBlob(t, signer)

	t.Run("reader failing after the headers", func(t *testing.T) {
		im := buildImage(spec{table: winCert(blob)})
		tableOff := im.segs[1].off
		boom := errors.New("boom")
		r := readerFunc(func(p []byte, off int64) (int, error) {
			if off >= tableOff {
				return 0, boom
			}
			return im.ReadAt(p, off)
		})
		signed, cert, err := parseSecurityDirectoryAt(r, im.size)
		if !errors.Is(err, boom) || !signed || cert != nil {
			t.Fatalf("got (%t, %v, %v), want (true, nil, boom)", signed, cert, err)
		}
	})

	t.Run("EOF together with a full read", func(t *testing.T) {
		// the signature blob ends exactly at the end of the file (no padding),
		// and the reader reports io.EOF alongside the last bytes, as os.File may
		im := buildImage(spec{table: winCert(blob)[:winCertHeaderSize+len(blob)]})
		r := readerFunc(func(p []byte, off int64) (int, error) {
			n, err := im.ReadAt(p, off)
			if err == nil && off+int64(n) == im.size {
				err = io.EOF
			}
			return n, err
		})
		signed, cert, err := parseSecurityDirectoryAt(r, im.size)
		if err != nil || !signed || cert == nil {
			t.Fatalf("got (%t, %v, %v), want a certificate", signed, cert, err)
		}
	})
}

type readerFunc func(p []byte, off int64) (int, error)

func (f readerFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

func TestSecurityDirectoryMatchesDebugPE(t *testing.T) {
	table := winCert(signBlob(t, newIdentity(t, fullName("Corp", "Signer"), big.NewInt(6), nil)))

	for _, s := range []spec{
		{table: table},
		{table: table, pe32: true},
		{table: table, padTo: 3 << 20},
		{table: table, pe32: true, padTo: 5<<20 + 3},
		{},
		{pe32: true},
	} {
		im := buildImage(s)
		f, err := debugpe.NewFile(bytes.NewReader(im.bytes()))
		if err != nil {
			t.Fatalf("debug/pe rejected the synthetic image: %v", err)
		}

		var want debugpe.DataDirectory
		switch oh := f.OptionalHeader.(type) {
		case *debugpe.OptionalHeader32:
			want = oh.DataDirectory[debugpe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		case *debugpe.OptionalHeader64:
			want = oh.DataDirectory[debugpe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}

		got, err := securityDirectory(im)
		if err != nil {
			t.Fatal(err)
		}
		if got.offset != want.VirtualAddress || got.size != want.Size {
			t.Errorf("spec %+v: got {%d %d}, debug/pe says {%d %d}", s.pe32, got.offset, got.size, want.VirtualAddress, want.Size)
		}
	}
}
