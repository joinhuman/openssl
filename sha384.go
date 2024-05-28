package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

type SHA384Hash struct {
	ctx    *C.EVP_MD_CTX
	engine *Engine
}

func NewSHA384Hash() (*SHA384Hash, error) { return NewSHA384HashWithEngine(nil) }

func NewSHA384HashWithEngine(e *Engine) (*SHA384Hash, error) {
	hash := &SHA384Hash{engine: e}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, errors.New("openssl: SHA384: unable to allocate ctx")
	}
	runtime.SetFinalizer(hash, func(hash *SHA384Hash) { hash.Close() })
	if err := hash.Reset(); err != nil {
		return nil, err
	}
	return hash, nil
}

func (s *SHA384Hash) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SHA384Hash) Reset() error {
	if 1 != C.X_EVP_DigestInit_ex(s.ctx, C.X_EVP_SHA384(), engineRef(s.engine)) {
		return errors.New("openssl: SHA384: cannot init digest ctx")
	}
	return nil
}

func (s *SHA384Hash) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if 1 != C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&p[0]),
		C.size_t(len(p))) {
		return 0, errors.New("openssl: SHA384: cannot update digest")
	}
	return len(p), nil
}

func (s *SHA384Hash) Sum() (result [64]byte, err error) {
	if 1 != C.X_EVP_DigestFinal_ex(s.ctx,
		(*C.uchar)(unsafe.Pointer(&result[0])), nil) {
		return result, errors.New("openssl: SHA384: cannot finalize ctx")
	}
	return result, s.Reset()
}

func SHA384(data []byte) (result [64]byte, err error) {
	hash, err := NewSHA384Hash()
	if err != nil {
		return result, err
	}
	defer hash.Close()
	if _, err := hash.Write(data); err != nil {
		return result, err
	}
	return hash.Sum()
}
