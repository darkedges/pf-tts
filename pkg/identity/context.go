package identity

import "context"

type contextKey struct{}

func WithContext(ctx context.Context, value RequestIdentityContext) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func FromContext(ctx context.Context) (RequestIdentityContext, bool) {
	value, ok := ctx.Value(contextKey{}).(RequestIdentityContext)
	return value, ok
}
