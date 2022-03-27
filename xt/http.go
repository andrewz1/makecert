package xt

import (
	"net/http"
)

func CloseReq(r *http.Request) {
	if r != nil && r.Body != nil {
		r.Body.Close()
	}
}
