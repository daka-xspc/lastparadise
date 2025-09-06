package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var adminUsername = "renoldadia"
var salt = "lastparadise-sdm"
var adminPasswordHash = "cb2ada22fca9ff3f4e7a3ebc72eb90df08a47133db1ddd88c0ef31af9b60c132"

var sessions = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

type Personnel struct {
	ID      int    `json:"ID"`
	Nama    string `json:"Nama"`
	Jabatan string `json:"Jabatan"`
	Pangkat string `json:"Pangkat"`
	Foto    string `json:"Foto"`
	Bio     string `json:"Bio"`
}

type node struct {
	Data Personnel
	Next *node
}

type listPersonnel struct {
	Head *node
	sync.RWMutex
}

var (
	personnelList = &listPersonnel{}
	templates     *template.Template
	dataFile      = "data.json"
	lastID        = 0
)

func main() {
	loadTemplates()
	if err := loadData(); err != nil {
		log.Printf("warning: failed load data: %v", err)
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/handbook", handbookHandler)
	http.HandleFunc("/tambah", requireAuth(addFormHandler))
	http.HandleFunc("/insert", requireAuth(insertHandler))
	http.HandleFunc("/edit", requireAuth(editFormHandler))
	http.HandleFunc("/update", requireAuth(updateHandler))
	http.HandleFunc("/delete", requireAuth(deleteHandler))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	addr := ":8080"
	fmt.Printf("Server berjalan di http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func loadTemplates() {
	pattern := filepath.Join("templates", "*.html")
	var err error
	templates, err = template.ParseGlob(pattern)
	if err != nil {
		log.Fatalf("failed parsing templates: %v", err)
	}
}

func handbookHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title": "Handbook SDM - Last Paradise",
		"year":  time.Now().Year(),
	}
	render(w, "handbook.html", data)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{
		"title": "Divisi SDM • Last Paradise",
		"year":  time.Now().Year(),
	}
	render(w, "index_home.html", data)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title":     "Daftar Personel - Divisi SDM",
		"personnel": readAll(),
		"year":      time.Now().Year(),
		"authed":    isAuthenticated(r),
	}
	render(w, "index.html", data)
}

func hashPassword(password string) string {
	h := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(h[:])
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "login.html", map[string]interface{}{
			"title": "Login Admin",
			"year":  time.Now().Year(),
		})
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if username != adminUsername || hashPassword(password) != adminPasswordHash {
			render(w, "login.html", map[string]interface{}{
				"error": "Username atau password salah",
				"year":  time.Now().Year(),
			})
			return
		}

		token := createSessionToken()
		sessions.Lock()
		sessions.m[token] = username
		sessions.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600,
		})
		http.Redirect(w, r, "/list", http.StatusSeeOther)
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err == nil {
		token := c.Value
		sessions.Lock()
		delete(sessions.m, token)
		sessions.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func isAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	sessions.RLock()
	_, ok := sessions.m[c.Value]
	sessions.RUnlock()
	return ok
}

func createSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func addFormHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title": "Tambah Personel",
		"year":  time.Now().Year(),
	}
	render(w, "form.html", data)
}

func insertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/list", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	nama := strings.TrimSpace(r.FormValue("nama"))
	jabatan := strings.TrimSpace(r.FormValue("jabatan"))
	pangkat := strings.TrimSpace(r.FormValue("pangkat"))
	foto := strings.TrimSpace(r.FormValue("foto"))
	bio := strings.TrimSpace(r.FormValue("bio"))

	if nama == "" || jabatan == "" || pangkat == "" {
		http.Error(w, "Nama, Jabatan, dan Pangkat wajib diisi.", http.StatusBadRequest)
		return
	}

	p := Personnel{ID: generateID(), Nama: nama, Jabatan: jabatan, Pangkat: pangkat, Foto: foto, Bio: bio}
	insert(p)
	if err := saveData(); err != nil {
		log.Printf("warning: save failed: %v", err)
	}
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func editFormHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	p, ok := getByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{
		"title": "Edit Personel",
		"p":     p,
		"year":  time.Now().Year(),
	}
	render(w, "edit.html", data)
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/list", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	nama := strings.TrimSpace(r.FormValue("nama"))
	jabatan := strings.TrimSpace(r.FormValue("jabatan"))
	pangkat := strings.TrimSpace(r.FormValue("pangkat"))
	foto := strings.TrimSpace(r.FormValue("foto"))
	bio := strings.TrimSpace(r.FormValue("bio"))

	p := Personnel{ID: id, Nama: nama, Jabatan: jabatan, Pangkat: pangkat, Foto: foto, Bio: bio}
	updated := update(p)
	if !updated {
		http.NotFound(w, r)
		return
	}
	if err := saveData(); err != nil {
		log.Printf("warning: save failed: %v", err)
	}
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	if id == 0 {
		http.Redirect(w, r, "/list", http.StatusSeeOther)
		return
	}
	deleted := deleteByID(id)
	if !deleted {
		http.NotFound(w, r)
		return
	}
	if err := saveData(); err != nil {
		log.Printf("warning: save failed: %v", err)
	}
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func generateID() int { lastID++; return lastID }

func insert(p Personnel) {
	personnelList.Lock()
	defer personnelList.Unlock()
	newNode := &node{Data: p}
	if personnelList.Head == nil {
		personnelList.Head = newNode
		return
	}
	cur := personnelList.Head
	for cur.Next != nil {
		cur = cur.Next
	}
	cur.Next = newNode
}

func readAll() []Personnel {
	personnelList.RLock()
	defer personnelList.RUnlock()
	var out []Personnel
	cur := personnelList.Head
	for cur != nil {
		out = append(out, cur.Data)
		cur = cur.Next
	}
	return out
}

func getByID(id int) (Personnel, bool) {
	personnelList.RLock()
	defer personnelList.RUnlock()
	cur := personnelList.Head
	for cur != nil {
		if cur.Data.ID == id {
			return cur.Data, true
		}
		cur = cur.Next
	}
	return Personnel{}, false
}

func update(updated Personnel) bool {
	personnelList.Lock()
	defer personnelList.Unlock()
	cur := personnelList.Head
	for cur != nil {
		if cur.Data.ID == updated.ID {
			cur.Data = updated
			return true
		}
		cur = cur.Next
	}
	return false
}

func deleteByID(id int) bool {
	personnelList.Lock()
	defer personnelList.Unlock()
	if personnelList.Head == nil {
		return false
	}
	if personnelList.Head.Data.ID == id {
		personnelList.Head = personnelList.Head.Next
		return true
	}
	prev := personnelList.Head
	cur := prev.Next
	for cur != nil {
		if cur.Data.ID == id {
			prev.Next = cur.Next
			return true
		}
		prev = cur
		cur = cur.Next
	}
	return false
}

func saveData() error {
	data := readAll()
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dataFile, b, 0644)
}

func loadData() error {
	if _, err := os.Stat(dataFile); os.IsNotExist(err) {
		return nil
	}
	b, err := os.ReadFile(dataFile)
	if err != nil {
		return err
	}
	var arr []Personnel
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	for _, p := range arr {
		insert(p)
		if p.ID > lastID {
			lastID = p.ID
		}
	}
	return nil
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var d map[string]interface{}
	if m, ok := data.(map[string]interface{}); ok {
		d = m
	} else {
		d = map[string]interface{}{"Data": data}
	}
	if err := templates.ExecuteTemplate(w, name, d); err != nil {
		log.Printf("render error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
