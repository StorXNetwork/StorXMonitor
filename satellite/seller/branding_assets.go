// Copyright (C) 2026 Storj Labs, Inc.
// See LICENSE for copying information.

package seller

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/errs"

	"github.com/StorXNetwork/common/uuid"
)

const (
	brandingAssetsRootDir   = "reseller"
	brandingAssetsURLPrefix = "/api/v0/seller/branding/assets"
	maxBrandingAssetSize    = 2 << 20 // 2 MiB
)

var allowedBrandingAssetExtensions = map[string]struct{}{
	".png":  {},
	".jpg":  {},
	".jpeg": {},
	".svg":  {},
	".webp": {},
	".ico":  {},
}

// BrandingAssets stores uploaded logos and favicons on local disk.
// All files live flat under {rootDir}/reseller/ with unique names:
// {resellerId}_{imageIdentifier}_{timestamp}_{uniqueId}.ext
type BrandingAssets struct {
	baseDir string
}

// NewBrandingAssets creates a branding asset store under {rootDir}/reseller/.
func NewBrandingAssets(rootDir string) (*BrandingAssets, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, errs.New("branding assets directory is not configured")
	}
	baseDir := filepath.Join(rootDir, brandingAssetsRootDir)
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	return &BrandingAssets{baseDir: baseDir}, nil
}

func (a *BrandingAssets) resellerFilePrefix(resellerID uuid.UUID) string {
	return resellerID.String() + "_"
}

func (a *BrandingAssets) Save(resellerID uuid.UUID, assetKey string, originalFilename string, contentType string, r io.Reader) (storedFilename string, err error) {
	ext, err := brandingAssetExtension(originalFilename, contentType)
	if err != nil {
		return "", err
	}

	storedFilename, err = a.uniqueStoredFilename(resellerID, assetKey, ext)
	if err != nil {
		return "", err
	}
	target := filepath.Join(a.baseDir, storedFilename)

	f, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer f.Close()

	written, err := io.Copy(f, io.LimitReader(r, maxBrandingAssetSize+1))
	if err != nil {
		_ = os.Remove(target)
		return "", err
	}
	if written > maxBrandingAssetSize {
		_ = os.Remove(target)
		return "", ErrValidation.New("file exceeds maximum size of 2 MiB")
	}

	return storedFilename, nil
}

func (a *BrandingAssets) PublicURL(resellerID uuid.UUID, storedFilename string) string {
	if storedFilename == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s", brandingAssetsURLPrefix, resellerID.String(), storedFilename)
}

func (a *BrandingAssets) Serve(w http.ResponseWriter, r *http.Request, resellerID uuid.UUID, filename string) {
	filename = filepath.Base(filename)
	if filename == "" || filename == "." {
		http.NotFound(w, r)
		return
	}
	if !strings.HasPrefix(filename, a.resellerFilePrefix(resellerID)) {
		http.NotFound(w, r)
		return
	}

	path := filepath.Join(a.baseDir, filename)
	if _, err := os.Stat(path); err != nil {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, path)
}

func (a *BrandingAssets) DeleteResellerAssets(resellerID uuid.UUID) error {
	prefix := a.resellerFilePrefix(resellerID)
	entries, err := os.ReadDir(a.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), prefix) {
			if err := os.Remove(filepath.Join(a.baseDir, entry.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func (a *BrandingAssets) DeleteFile(resellerID uuid.UUID, storedFilename string) error {
	if strings.TrimSpace(storedFilename) == "" {
		return nil
	}
	filename := filepath.Base(storedFilename)
	if !strings.HasPrefix(filename, a.resellerFilePrefix(resellerID)) {
		return nil
	}
	path := filepath.Join(a.baseDir, filename)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (a *BrandingAssets) uniqueStoredFilename(resellerID uuid.UUID, assetKey, ext string) (string, error) {
	id, err := uuid.New()
	if err != nil {
		return "", err
	}
	shortID := strings.ReplaceAll(id.String(), "-", "")[:12]
	identifier := sanitizeBrandingAssetKey(assetKey)
	return fmt.Sprintf("%s_%s_%d_%s%s", resellerID.String(), identifier, time.Now().UnixMilli(), shortID, ext), nil
}

func brandingAssetExtension(originalFilename, contentType string) (string, error) {
	ext := strings.ToLower(filepath.Ext(originalFilename))
	if ext != "" {
		if _, ok := allowedBrandingAssetExtensions[ext]; ok {
			return ext, nil
		}
	}

	// Original filename may be missing or invalid — infer from Content-Type.
	switch strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0])) {
	case "image/png":
		return ".png", nil
	case "image/jpeg":
		return ".jpg", nil
	case "image/svg+xml":
		return ".svg", nil
	case "image/webp":
		return ".webp", nil
	case "image/x-icon", "image/vnd.microsoft.icon":
		return ".ico", nil
	}

	if ext == "" {
		return "", ErrValidation.New("could not detect image type (use png, jpg, jpeg, svg, webp, or ico)")
	}
	return "", ErrValidation.New("unsupported file type %q (use png, jpg, jpeg, svg, webp, or ico)", ext)
}

func sanitizeBrandingAssetKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.ReplaceAll(key, "/", "_")
	key = strings.ReplaceAll(key, "\\", "_")
	return key
}

func enrichBrandingConfigURLs(cfg ResellerBrandingConfig, resellerID uuid.UUID) ResellerBrandingConfig {
	logo := make(map[string]string, len(cfg.Logo))
	for k, v := range cfg.Logo {
		logo[k] = brandingAssetPublicURL(resellerID, v)
	}
	cfg.Logo = logo
	cfg.Favicon = brandingAssetPublicURL(resellerID, cfg.Favicon)
	return cfg
}

func enrichBrandingViewURLs(view ResellerBrandingView, resellerID uuid.UUID) ResellerBrandingView {
	view.ResellerBrandingConfig = enrichBrandingConfigURLs(view.ResellerBrandingConfig, resellerID)
	return view
}

func brandingAssetPublicURL(resellerID uuid.UUID, storedFilename string) string {
	if storedFilename == "" {
		return ""
	}
	if strings.HasPrefix(storedFilename, "/") {
		return storedFilename
	}
	return fmt.Sprintf("%s/%s/%s", brandingAssetsURLPrefix, resellerID.String(), storedFilename)
}
