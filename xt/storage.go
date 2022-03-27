package xt

import (
	"sync"
)

type Storage struct {
	sync.RWMutex
	m map[string]interface{}
}

func NewStorage() *Storage {
	return &Storage{m: make(map[string]interface{})}
}

func (s *Storage) Get(k string) interface{} {
	s.RLock()
	defer s.RUnlock()
	if v, ok := s.m[k]; ok {
		return v
	}
	return nil
}

func (s *Storage) Put(k string, v interface{}) {
	s.Lock()
	s.m[k] = v
	s.Unlock()
}

func (s *Storage) Del(k string) {
	s.Lock()
	delete(s.m, k)
	s.Unlock()
}
