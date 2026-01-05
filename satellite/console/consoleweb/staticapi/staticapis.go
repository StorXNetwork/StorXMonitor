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

func HandleUserGuideline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write(userGuideline)
}

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
