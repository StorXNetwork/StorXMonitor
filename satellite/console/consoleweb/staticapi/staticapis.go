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

//go:embed signup-guide.html
var signupGuide []byte

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

	case "google-backup":
		w.Write(googleBackupGuide)

	case "microsoft-backup":
		w.Write(microsoftBackupGuide)

	case "signup":
		w.Write(signupGuide)

	default:
		http.Error(w, "Guide not found", http.StatusNotFound)
	}
}
