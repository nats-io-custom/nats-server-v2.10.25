package internal

import "context"

var _ctx context.Context

func SetContext(ctx context.Context) {
	_ctx = ctx
}
func GetContext() context.Context {
	return _ctx
}
