package main

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const (
	defaultListenAddr       = ":8080"
	defaultDataDir          = "/data"
	defaultCacheTTL         = 24 * time.Hour
	defaultJobTTL           = 24 * time.Hour
	defaultCleanupInterval  = 15 * time.Minute
	defaultRequestTimeout   = 45 * time.Minute
	defaultMaxConcurrent    = 2
	defaultUserAgent        = "image-pack-webserver"
	maxRequestBodyBytes     = 1 << 20
	statusQueued            = "queued"
	statusRunning           = "running"
	statusReady             = "ready"
	statusFailed            = "failed"
	cacheExtension          = ".tar"
	authFingerprintAnonPart = "anonymous"
)

var (
	errNotFound      = errors.New("not found")
	cacheKeyPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	jobIDPattern     = regexp.MustCompile(`^[a-z2-7]{26}$`)
	fileNameReplacer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
)

type Config struct {
	ListenAddr      string
	DataDir         string
	PublicBaseURL   string
	BasicAuthUser   string
	BasicAuthPass   string
	CacheTTL        time.Duration
	JobTTL          time.Duration
	CleanupInterval time.Duration
	RequestTimeout  time.Duration
	MaxConcurrent   int
	UserAgent       string
}

func loadConfig() Config {
	return Config{
		ListenAddr:      envString("LISTEN_ADDR", defaultListenAddr),
		DataDir:         envString("DATA_DIR", defaultDataDir),
		PublicBaseURL:   strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
		BasicAuthUser:   os.Getenv("BASIC_AUTH_USER"),
		BasicAuthPass:   os.Getenv("BASIC_AUTH_PASSWORD"),
		CacheTTL:        envDuration("CACHE_TTL", defaultCacheTTL),
		JobTTL:          envDuration("JOB_TTL", defaultJobTTL),
		CleanupInterval: envDuration("CLEANUP_INTERVAL", defaultCleanupInterval),
		RequestTimeout:  envDuration("REQUEST_TIMEOUT", defaultRequestTimeout),
		MaxConcurrent:   envInt("MAX_CONCURRENT_DOWNLOADS", defaultMaxConcurrent),
		UserAgent:       envString("USER_AGENT", defaultUserAgent),
	}
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

type ImageRequest struct {
	Image    string `json:"image"`
	Platform string `json:"platform,omitempty"`

	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RegistryToken string `json:"registry_token,omitempty"`
	Auth          string `json:"auth,omitempty"`
}

type RegistryCredentials struct {
	Username      string
	Password      string
	RegistryToken string
	Auth          string
}

func (c RegistryCredentials) empty() bool {
	return c.Username == "" && c.Password == "" && c.RegistryToken == "" && c.Auth == ""
}

func (c RegistryCredentials) authenticator() authn.Authenticator {
	if c.empty() {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      c.Username,
		Password:      c.Password,
		RegistryToken: c.RegistryToken,
		Auth:          c.Auth,
	})
}

func (c RegistryCredentials) fingerprint() string {
	if c.empty() {
		return authFingerprintAnonPart
	}
	h := sha256.New()
	writePart := func(value string) {
		_, _ = h.Write([]byte(value))
		_, _ = h.Write([]byte{0})
	}
	writePart(c.Username)
	writePart(c.Password)
	writePart(c.RegistryToken)
	writePart(c.Auth)
	return hex.EncodeToString(h.Sum(nil))
}

func credentialsFromRequest(payload ImageRequest, r *http.Request) RegistryCredentials {
	credentials := RegistryCredentials{
		Username:      strings.TrimSpace(payload.Username),
		Password:      payload.Password,
		RegistryToken: strings.TrimSpace(payload.RegistryToken),
		Auth:          strings.TrimSpace(payload.Auth),
	}
	if credentials.Username == "" {
		credentials.Username = strings.TrimSpace(r.Header.Get("X-Registry-Username"))
	}
	if credentials.Password == "" {
		credentials.Password = r.Header.Get("X-Registry-Password")
	}
	if credentials.RegistryToken == "" {
		credentials.RegistryToken = strings.TrimSpace(r.Header.Get("X-Registry-Token"))
	}
	if credentials.Auth == "" {
		credentials.Auth = strings.TrimSpace(r.Header.Get("X-Registry-Auth"))
	}
	return credentials
}

type Job struct {
	ID          string     `json:"id"`
	Image       string     `json:"image"`
	Platform    string     `json:"platform,omitempty"`
	Status      string     `json:"status"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	DownloadURL string     `json:"download_url,omitempty"`
	StatusURL   string     `json:"status_url"`

	cacheKey string
	fileName string
}

type JobResponse struct {
	ID          string     `json:"id"`
	Image       string     `json:"image"`
	Platform    string     `json:"platform,omitempty"`
	Status      string     `json:"status"`
	Error       string     `json:"error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	DownloadURL string     `json:"download_url,omitempty"`
	StatusURL   string     `json:"status_url"`
}

type PackRequest struct {
	Image       string
	Platform    string
	Credentials RegistryCredentials
}

type Packer interface {
	Pack(ctx context.Context, req PackRequest, targetPath string) error
}

type ContainerRegistryPacker struct {
	UserAgent string
}

func (p ContainerRegistryPacker) Pack(ctx context.Context, req PackRequest, targetPath string) error {
	ref, err := name.ParseReference(req.Image, name.WeakValidation)
	if err != nil {
		return fmt.Errorf("parse image reference: %w", err)
	}

	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(req.Credentials.authenticator()),
		remote.WithUserAgent(p.UserAgent),
	}
	if req.Platform != "" {
		platform, err := parsePlatform(req.Platform)
		if err != nil {
			return err
		}
		opts = append(opts, remote.WithPlatform(*platform))
	}

	img, err := remote.Image(ref, opts...)
	if err != nil {
		return fmt.Errorf("pull image: %w", err)
	}

	file, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	gz := gzip.NewWriter(file)
	if err := tarball.Write(ref, img, gz); err != nil {
		_ = gz.Close()
		return fmt.Errorf("write archive: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("finish archive: %w", err)
	}
	return nil
}

func parsePlatform(raw string) (*v1.Platform, error) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid platform %q, expected os/arch or os/arch/variant", raw)
	}
	platform := &v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		platform.Variant = parts[2]
	}
	return platform, nil
}

type Server struct {
	cfg    Config
	packer Packer
	logger *slog.Logger
	sem    chan struct{}

	mu    sync.Mutex
	jobs  map[string]*Job
	byKey map[string]string
}

func NewServer(cfg Config, packer Packer, logger *slog.Logger) (*Server, error) {
	if cfg.MaxConcurrent < 1 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	for _, dir := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "cache"), filepath.Join(cfg.DataDir, "tmp")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return &Server{
		cfg:    cfg,
		packer: packer,
		logger: logger,
		sem:    make(chan struct{}, cfg.MaxConcurrent),
		jobs:   make(map[string]*Job),
		byKey:  make(map[string]string),
	}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /api/images", s.handleCreateImage)
	mux.HandleFunc("GET /api/images", s.handleCreateImage)
	mux.HandleFunc("GET /api/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/downloads/{key}/{filename}", s.handleDownload)
	return s.withBasicAuth(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "image-pack-webserver",
		"endpoints": map[string]string{
			"create":   "POST /api/images",
			"status":   "GET /api/jobs/{id}",
			"download": "GET /api/downloads/{key}/{filename}",
		},
	})
}

func (s *Server) handleCreateImage(w http.ResponseWriter, r *http.Request) {
	payload, err := decodeImageRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ref, err := name.ParseReference(payload.Image, name.WeakValidation)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image reference")
		return
	}
	if payload.Platform != "" {
		if _, err := parsePlatform(payload.Platform); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	normalized := ref.Name()
	credentials := credentialsFromRequest(payload, r)
	key := cacheKey(normalized, payload.Platform, credentials)
	fileName := archiveFileName(normalized, payload.Platform, key)

	job, ready, created, err := s.prepareJob(normalized, payload.Platform, key, fileName, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if created && !ready {
		go s.runJob(job.ID, PackRequest{
			Image:       normalized,
			Platform:    payload.Platform,
			Credentials: credentials,
		})
	}

	status := http.StatusAccepted
	if ready {
		status = http.StatusOK
	}
	writeJSON(w, status, job)
}

func decodeImageRequest(r *http.Request) (ImageRequest, error) {
	var payload ImageRequest
	switch r.Method {
	case http.MethodGet:
		payload.Image = strings.TrimSpace(r.URL.Query().Get("image"))
		payload.Platform = strings.TrimSpace(r.URL.Query().Get("platform"))
	case http.MethodPost:
		defer func() {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}()
		decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			return payload, fmt.Errorf("invalid JSON request body")
		}
	default:
		return payload, fmt.Errorf("method not allowed")
	}
	payload.Image = strings.TrimSpace(payload.Image)
	payload.Platform = strings.TrimSpace(payload.Platform)
	if payload.Image == "" {
		return payload, fmt.Errorf("image is required")
	}
	return payload, nil
}

func (s *Server) prepareJob(image, platform, key, fileName string, r *http.Request) (JobResponse, bool, bool, error) {
	now := time.Now().UTC()
	if s.cacheExists(key) {
		_ = os.Chtimes(s.cachePath(key), now, now)
		job := &Job{
			ID:          mustRandomID(),
			Image:       image,
			Platform:    platform,
			Status:      statusReady,
			CreatedAt:   now,
			UpdatedAt:   now,
			CompletedAt: &now,
			cacheKey:    key,
			fileName:    fileName,
		}
		s.mu.Lock()
		s.jobs[job.ID] = job
		s.byKey[key] = job.ID
		response := s.jobResponseLocked(job, r)
		s.mu.Unlock()
		return response, true, true, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existingID, ok := s.byKey[key]; ok {
		if existing, ok := s.jobs[existingID]; ok {
			return s.jobResponseLocked(existing, r), existing.Status == statusReady, false, nil
		}
		delete(s.byKey, key)
	}

	job := &Job{
		ID:        mustRandomID(),
		Image:     image,
		Platform:  platform,
		Status:    statusQueued,
		CreatedAt: now,
		UpdatedAt: now,
		cacheKey:  key,
		fileName:  fileName,
	}
	s.jobs[job.ID] = job
	s.byKey[key] = job.ID
	return s.jobResponseLocked(job, r), false, true, nil
}

func (s *Server) runJob(jobID string, req PackRequest) {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.updateJob(jobID, func(job *Job) {
		job.Status = statusRunning
		job.UpdatedAt = time.Now().UTC()
	})

	job, ok := s.snapshotJob(jobID)
	if !ok {
		return
	}

	if s.cacheExists(job.cacheKey) {
		s.markReady(jobID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
	defer cancel()

	tmpPath := filepath.Join(s.cfg.DataDir, "tmp", job.cacheKey+"-"+job.ID+".tar")
	finalPath := s.cachePath(job.cacheKey)
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := s.packer.Pack(ctx, req, tmpPath); err != nil {
		s.markFailed(jobID, err)
		return
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		s.markFailed(jobID, fmt.Errorf("store archive: %w", err))
		return
	}
	s.markReady(jobID)
}

func (s *Server) snapshotJob(jobID string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return nil, false
	}
	copy := *job
	return &copy, true
}

func (s *Server) updateJob(jobID string, update func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[jobID]; ok {
		update(job)
	}
}

func (s *Server) markReady(jobID string) {
	now := time.Now().UTC()
	s.updateJob(jobID, func(job *Job) {
		job.Status = statusReady
		job.Error = ""
		job.UpdatedAt = now
		job.CompletedAt = &now
	})
}

func (s *Server) markFailed(jobID string, err error) {
	now := time.Now().UTC()
	s.logger.Error("image packing failed", "job_id", jobID, "error", err)
	s.updateJob(jobID, func(job *Job) {
		job.Status = statusFailed
		job.Error = err.Error()
		job.UpdatedAt = now
		job.CompletedAt = &now
	})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !jobIDPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		writeError(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.jobResponseLocked(job, r))
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !cacheKeyPattern.MatchString(key) {
		writeError(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	path := s.cachePath(key)
	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusNotFound, errNotFound.Error())
		return
	}
	now := time.Now().UTC()
	_ = os.Chtimes(path, now, now)

	filename := r.PathValue("filename")
	if filename == "" || strings.Contains(filename, "/") {
		filename = key + cacheExtension
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeHeaderFileName(filename)))
	http.ServeContent(w, r, filename, info.ModTime(), file)
}

func (s *Server) jobResponseLocked(job *Job, r *http.Request) JobResponse {
	response := JobResponse{
		ID:          job.ID,
		Image:       job.Image,
		Platform:    job.Platform,
		Status:      job.Status,
		Error:       job.Error,
		CreatedAt:   job.CreatedAt,
		UpdatedAt:   job.UpdatedAt,
		CompletedAt: job.CompletedAt,
		StatusURL:   absoluteURL(s.cfg.PublicBaseURL, r, "/api/jobs/"+job.ID),
	}
	if job.Status == statusReady {
		response.DownloadURL = absoluteURL(s.cfg.PublicBaseURL, r, "/api/downloads/"+job.cacheKey+"/"+job.fileName)
	}
	return response
}

func absoluteURL(publicBaseURL string, r *http.Request, path string) string {
	if publicBaseURL != "" {
		return publicBaseURL + path
	}
	scheme := firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + path
}

func firstHeaderValue(raw string) string {
	if raw == "" {
		return ""
	}
	value, _, _ := strings.Cut(raw, ",")
	return strings.TrimSpace(value)
}

func (s *Server) cachePath(key string) string {
	return filepath.Join(s.cfg.DataDir, "cache", key+cacheExtension)
}

func (s *Server) cacheExists(key string) bool {
	info, err := os.Stat(s.cachePath(key))
	return err == nil && !info.IsDir()
}

func (s *Server) withBasicAuth(next http.Handler) http.Handler {
	if s.cfg.BasicAuthUser == "" && s.cfg.BasicAuthPass == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.cfg.BasicAuthUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.BasicAuthPass)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="image-packer"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Server) cleanup() {
	now := time.Now().UTC()
	cacheCutoff := now.Add(-s.cfg.CacheTTL)
	jobCutoff := now.Add(-s.cfg.JobTTL)

	cacheEntries, err := os.ReadDir(filepath.Join(s.cfg.DataDir, "cache"))
	if err == nil {
		for _, entry := range cacheEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), cacheExtension) {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.ModTime().After(cacheCutoff) {
				continue
			}
			path := filepath.Join(s.cfg.DataDir, "cache", entry.Name())
			if err := os.Remove(path); err != nil {
				s.logger.Warn("failed to remove expired cache entry", "path", path, "error", err)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, job := range s.jobs {
		if job.Status != statusReady && job.Status != statusFailed {
			continue
		}
		if job.UpdatedAt.After(jobCutoff) {
			continue
		}
		delete(s.jobs, id)
		if s.byKey[job.cacheKey] == id {
			delete(s.byKey, job.cacheKey)
		}
	}
}

func cacheKey(image, platform string, credentials RegistryCredentials) string {
	h := sha256.New()
	_, _ = h.Write([]byte(image))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(platform))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(credentials.fingerprint()))
	return hex.EncodeToString(h.Sum(nil))
}

func archiveFileName(image, platform, key string) string {
	base := fileNameReplacer.ReplaceAllString(image, "_")
	base = strings.Trim(base, "._-")
	if base == "" {
		base = "image"
	}
	if platform != "" {
		base += "_" + fileNameReplacer.ReplaceAllString(platform, "_")
	}
	if len(base) > 96 {
		base = base[:96]
	}
	return base + "-" + key[:12] + cacheExtension
}

func sanitizeHeaderFileName(filename string) string {
	filename = strings.ReplaceAll(filename, `"`, "")
	filename = strings.ReplaceAll(filename, "\r", "")
	filename = strings.ReplaceAll(filename, "\n", "")
	if filename == "" {
		return "image" + cacheExtension
	}
	return filename
}

func mustRandomID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return strings.ToLower(encoded)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		if err := runHealthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfg := loadConfig()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	server, err := NewServer(cfg, ContainerRegistryPacker{UserAgent: cfg.UserAgent}, logger)
	if err != nil {
		logger.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.cleanupLoop(ctx)

	logger.Info("starting image packer", "addr", cfg.ListenAddr, "data_dir", cfg.DataDir)
	if err := http.ListenAndServe(cfg.ListenAddr, server.routes()); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func runHealthcheck() error {
	url := envString("HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz")
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("healthcheck returned HTTP %d", resp.StatusCode)
	}
	return nil
}
