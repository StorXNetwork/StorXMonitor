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

// Google/Microsoft/Corporate mail backup guides are hidden from Resources for now
// (kept embedded so they can be re-enabled without removing files).
//
//go:embed google-backup-guide.html
var googleBackupGuide []byte

//go:embed microsoft-backup-guide.html
var microsoftBackupGuide []byte

//go:embed corporate-mail-backup-guide.html
var corporateMailBackupGuide []byte

//go:embed signup-guide.html
var signupGuide []byte

// Prevent unused-var build errors while guides are hidden from Resources.
var _ = [][]byte{googleBackupGuide, microsoftBackupGuide, corporateMailBackupGuide}

func HandleResources(w http.ResponseWriter, r *http.Request) {

	if r.URL.Query().Get("app") == "true" {
		w.Header().Set("Content-Type", "application/json")
		w.Write(appResources)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(resources)
	}
}

func HandleBlogList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(blogList)
}

func HandleUserGuidelineforApp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write(userGuidelineforApp)
}

func HandleGuides(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	switch r.URL.Query().Get("type") {
	case "usage-guideline":
		w.Write(userGuideline)

	// Hidden for binary update: Google / Microsoft / Corporate mail backup guides.
	// case "google-backup":
	// 	w.Write(googleBackupGuide)
	// case "microsoft-backup":
	// 	w.Write(microsoftBackupGuide)
	// case "corporate-mail-backup":
	// 	w.Write(corporateMailBackupGuide)

	case "signup":
		w.Write(signupGuide)

	default:
		http.Error(w, "Guide not found", http.StatusNotFound)
	}
}
