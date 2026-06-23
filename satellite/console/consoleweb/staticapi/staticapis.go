package staticapi

import (
	_ "embed"
	"net/http"
)

//go:embed blog-list.json
var blogList []byte

//go:embed user-guideline.html
var userGuideline []byte

//go:embed resources.json
var resources []byte

//go:embed app-resources.json
var appResources []byte

//go:embed user-guideline-for-app.html
var userGuidelineforApp []byte

//go:embed google-backup-guide.html
var googleBackupGuide []byte

//go:embed microsoft-backup-guide.html
var microsoftBackupGuide []byte

//go:embed corporate-mail-backup-guide.html
var corporateMailBackupGuide []byte

//go:embed signup-guide.html
var signupGuide []byte

// HandleResources returns curated help links for the web console or mobile app.
//
// @Summary      List help resources
// @Description  **Full route:** `GET /resources-list` (server root, not under `/api/v0`).
//
// Returns a JSON array of resource cards (guides, blogs, contact). Pass `app=true` for the mobile app list (fewer entries, app-specific usage guideline link).
// @Tags         static-api
// @Produce      json
// @Param        app  query  bool  false  "If true, returns app-specific resources (app-resources.json)"
// @Success      200  {array}   StaticResourceItemSwagger
// @Router       /resources-list [get]
func HandleResources(w http.ResponseWriter, r *http.Request) {

	if r.URL.Query().Get("app") == "true" {
		w.Header().Set("Content-Type", "application/json")
		w.Write(appResources)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(resources)
	}
}

// HandleBlogList returns featured Medium blog posts for the console resources page.
//
// @Summary      List featured blogs
// @Description  **Full route:** `GET /blog-list` (server root, not under `/api/v0`).
//
// Public JSON feed of blog cards (image, title, description, author, date, link).
// @Tags         static-api
// @Produce      json
// @Success      200  {array}   StaticBlogItemSwagger
// @Router       /blog-list [get]
func HandleBlogList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(blogList)
}

// HandleUserGuidelineforApp returns the mobile app usage guideline HTML page.
//
// @Summary      Mobile app usage guideline
// @Description  **Full route:** `GET /user-guideline-for-app` (server root, not under `/api/v0`).
//
// Serves embedded HTML documentation for the StorX mobile app (vaults, sharing, etc.).
// @Tags         static-api
// @Produce      html
// @Success      200  {string}  string  "HTML usage guideline page"
// @Router       /user-guideline-for-app [get]
func HandleUserGuidelineforApp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write(userGuidelineforApp)
}

// HandleGuides returns an HTML documentation guide selected by query parameter.
//
// @Summary      Get documentation guide
// @Description  **Full route:** `GET /guides` (server root, not under `/api/v0`).
//
// Serves embedded HTML guides. Use the `type` query parameter to select which guide to return.
// @Tags         static-api
// @Produce      html
// @Param        type  query  string  true  "Guide identifier"  Enums(usage-guideline, google-backup, microsoft-backup, corporate-mail-backup, signup)
// @Success      200   {string}  string  "HTML guide page"
// @Failure      404   {string}  string  "Guide not found"
// @Failure      405   {string}  string  "Method Not Allowed"
// @Router       /guides [get]
func HandleGuides(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	switch r.URL.Query().Get("type") {
	case "usage-guideline":
		w.Write(userGuideline)

	case "google-backup":
		w.Write(googleBackupGuide)

	case "microsoft-backup":
		w.Write(microsoftBackupGuide)

	case "corporate-mail-backup":
		w.Write(corporateMailBackupGuide)

	case "signup":
		w.Write(signupGuide)

	default:
		http.Error(w, "Guide not found", http.StatusNotFound)
	}
}
