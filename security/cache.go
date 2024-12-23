package security

import (
	"crypto/x509"
	"runtime"
	"sync"
	"sync/atomic"
)

type cacheEntry struct {
	refs atomic.Int64
	cert *x509.Certificate
}

type activeCert struct {
	cert *x509.Certificate
}

var globalCertCache = new(certCache)

type certCache struct {
	sync.Map
}

func (cc *certCache) active(e *cacheEntry) *activeCert {
	e.refs.Add(1)
	a := &activeCert{e.cert}
	runtime.SetFinalizer(a, func(_ *activeCert) {
		if e.refs.Add(-1) == 0 {
			cc.evict(e)
		}
	})
	return a
}

func (cc *certCache) evict(e *cacheEntry) {
	cc.Delete(string(e.cert.Raw))
}

func (cc *certCache) newCert(der []byte) (*activeCert, error) {
	if entry, ok := cc.Load(string(der)); ok {
		return cc.active(entry.(*cacheEntry)), nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	entry := &cacheEntry{cert: cert}
	if entry, loaded := cc.LoadOrStore(string(der), entry); loaded {
		return cc.active(entry.(*cacheEntry)), nil
	}
	return cc.active(entry), nil
}
