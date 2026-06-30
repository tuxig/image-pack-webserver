package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type fakePacker struct{}

func (fakePacker) Pack(_ context.Context, _ PackRequest, targetPath string) error {
	return os.WriteFile(targetPath, []byte("fake archive"), 0o644)
}

func testServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":0"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.JobTTL == 0 {
		cfg.JobTTL = time.Hour
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Hour
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = time.Minute
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 1
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "test"
	}
	server, err := NewServer(cfg, fakePacker{}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func TestBasicAuthProtectsAPIButNotHealth(t *testing.T) {
	server := testServer(t, Config{BasicAuthUser: "admin", BasicAuthPass: "secret"})
	handler := server.routes()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/images?image=busybox", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.Code, http.StatusUnauthorized)
	}

	authorizedReq := httptest.NewRequest(http.MethodGet, "/api/images?image=busybox", nil)
	authorizedReq.SetBasicAuth("admin", "secret")
	authorized := httptest.NewRecorder()
	handler.ServeHTTP(authorized, authorizedReq)
	if authorized.Code != http.StatusAccepted {
		t.Fatalf("authorized status = %d, want %d; body=%s", authorized.Code, http.StatusAccepted, authorized.Body.String())
	}
}

func TestCacheHitReturnsReadyWithForwardedURL(t *testing.T) {
	server := testServer(t, Config{})
	image := "index.docker.io/library/busybox:latest"
	key := cacheKey(image, "", RegistryCredentials{})
	if err := os.WriteFile(server.cachePath(key), []byte("cached"), 0o644); err != nil {
		t.Fatalf("write cache fixture: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/images?image=busybox", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "images.example.test")
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"ready"`) {
		t.Fatalf("response missing ready status: %s", body)
	}
	if !strings.Contains(body, `"download_url":"https://images.example.test/api/downloads/`) {
		t.Fatalf("response missing forwarded download URL: %s", body)
	}
}

func TestCacheKeySeparatesCredentialsAndPlatform(t *testing.T) {
	anonymous := cacheKey("example.com/app:latest", "", RegistryCredentials{})
	withCreds := cacheKey("example.com/app:latest", "", RegistryCredentials{
		Username: "u",
		Password: "p",
	})
	withPlatform := cacheKey("example.com/app:latest", "linux/arm64", RegistryCredentials{})

	if anonymous == withCreds {
		t.Fatal("anonymous and credentialed cache keys should differ")
	}
	if anonymous == withPlatform {
		t.Fatal("platform-specific cache key should differ")
	}
}

func TestParsePlatform(t *testing.T) {
	platform, err := parsePlatform("linux/arm64/v8")
	if err != nil {
		t.Fatalf("parsePlatform() error = %v", err)
	}
	if platform.OS != "linux" || platform.Architecture != "arm64" || platform.Variant != "v8" {
		t.Fatalf("platform = %#v", platform)
	}

	if _, err := parsePlatform("linux"); err == nil {
		t.Fatal("parsePlatform() expected error for incomplete platform")
	}
}
