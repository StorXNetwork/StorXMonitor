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

func HandleUserGuideline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write(userGuideline)
}

func HandleResources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(resources)
}

func HandleBlogList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(blogList)
}
