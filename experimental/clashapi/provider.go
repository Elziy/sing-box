package clashapi

import (
	"context"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func proxyProviderRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders(server))

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName(server))
		r.Get("/", getProvider(server))
		r.Put("/", updateProvider)
		r.Get("/healthcheck", healthCheckProvider)
	})
	return r
}

func getProviders(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		providerMap := make(render.M)
		for _, provider := range server.provider.Providers() {
			providerMap[provider.Tag()] = providerInfo(server, provider)
		}
		render.JSON(w, r, render.M{
			"providers": providerMap,
		})
	}
}

func getProvider(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
		render.JSON(w, r, providerInfo(server, provider))
	}
}

func providerInfo(server *Server, p adapter.Provider) *badjson.JSONObject {
	var info badjson.JSONObject
	proxies := make([]*badjson.JSONObject, 0)
	for _, detour := range p.Outbounds() {
		proxies = append(proxies, proxyInfo(server, detour))
	}
	info.Put("type", "Proxy")
	info.Put("vehicleType", C.ProviderDisplayName(p.Type()))
	info.Put("icon", p.Icon())
	info.Put("name", p.Tag())
	info.Put("proxies", proxies)
	info.Put("updatedAt", p.UpdatedTime())
	if p, ok := p.(adapter.ProviderSubscriptionInfo); ok && p.SubscriptionInfo() != nil {
		info.Put("subscriptionInfo", p.SubscriptionInfo())
	} else {
		info.Put("subscriptionInfo", &adapter.SubscriptionInfo{
			Upload:   0,
			Download: 0,
			Total:    0,
			Expire:   0,
		})
	}
	return &info
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	if err := provider.UpdateProvider(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func healthCheckProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(adapter.Provider)
	_, _ = provider.HealthCheck(r.Context())
	render.NoContent(w, r)
}

func parseProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderByName(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyProviderName).(string)
			provider, exist := server.provider.Get(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
