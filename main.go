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

var salt = "lastparadise-sdm"

// Admin
var adminUsername = "renoldadia"
var adminPasswordHash = "cb2ada22fca9ff3f4e7a3ebc72eb90df08a47133db1ddd88c0ef31af9b60c132"

// --- SESSION HANDLING ---
var sessions = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

var userSessions = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// --- STRUCTS ---
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // user atau admin
}

type Registration struct {
	ID       int       `json:"id"`
	Username string    `json:"username"`
	Nama     string    `json:"nama"`
	Pangkat  string    `json:"pangkat"`
	Divisi   string    `json:"divisi"`
	Q1       string    `json:"q1"`
	Q2       string    `json:"q2"`
	Q3       string    `json:"q3"`
	Q4       string    `json:"q4"`
	Status   string    `json:"status"` // pending, denied, accept
	Date     time.Time `json:"date"`
}

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

// --- GLOBAL ---
var (
	personnelList    = &listPersonnel{}
	templates        *template.Template
	personnelFile    = "personnel.json"
	usersFile        = "users.json"
	registrationFile = "registrations.json"
	lastID           = 0
	lastRegID        = 0
	users            = []User{}
	registrations    = []Registration{}
)

func main() {
	loadTemplates()
	loadPersonnel()
	loadUsers()
	loadRegistrations()

	// Routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/list", listHandler)
	http.HandleFunc("/login", loginChoiceHandler)
	http.HandleFunc("/login/admin", loginAdminHandler)
	http.HandleFunc("/login/user", loginUserHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/status", requireUser(statusHandler))
	http.HandleFunc("/handbook", handbookHandler)
	http.HandleFunc("/apply", requireUser(applyHandler))

	// Admin only
	http.HandleFunc("/admin/registrations", requireAdmin(adminRegistrationsHandler))
	http.HandleFunc("/admin/registrations/update", requireAdmin(updateRegistrationStatusHandler))
	http.HandleFunc("/admin/pending", requireAdmin(pendingHandler))
	http.HandleFunc("/registrations", registrationsHandler)

	// Personnel CRUD (admin only)
	http.HandleFunc("/tambah", requireAdmin(addFormHandler))
	http.HandleFunc("/insert", requireAdmin(insertHandler))
	http.HandleFunc("/edit", requireAdmin(editFormHandler))
	http.HandleFunc("/update", requireAdmin(updateHandler))
	http.HandleFunc("/delete", requireAdmin(deleteHandler))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	addr := ":8080"
	fmt.Printf("Server berjalan di http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// =================== TEMPLATE ===================
func loadTemplates() {
	pattern := filepath.Join("templates", "*.html")
	var err error
	templates, err = template.ParseGlob(pattern)
	if err != nil {
		log.Fatalf("failed parsing templates: %v", err)
	}
}

func registrationsHandler(w http.ResponseWriter, r *http.Request) {
	// Pastikan hanya admin yang bisa mengakses halaman ini
	if !isAdmin(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	loadRegistrations()
	data := map[string]interface{}{
		"title":         "Daftar Pendaftar",
		"registrations": registrations,
	}
	render(w, "registrations.html", data)
}

func pendingHandler(w http.ResponseWriter, r *http.Request) {
	// Memuat data pendaftaran
	loadRegistrations()

	data := map[string]interface{}{
		"title":         "Daftar Anggota Pending",
		"registrations": registrations,
	}
	render(w, "pending.html", data)
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// =================== PASSWORD ===================
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(h[:])
}

// =================== AUTH ===================
func createToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := isUser(r) // hanya pakai bool
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func isAdmin(r *http.Request) bool {
	c, err := r.Cookie("admin_token")
	if err != nil {
		return false
	}
	sessions.RLock()
	_, ok := sessions.m[c.Value]
	sessions.RUnlock()
	return ok
}

func isUser(r *http.Request) (string, bool) {
	c, err := r.Cookie("user_token")
	if err != nil {
		return "", false
	}
	userSessions.RLock()
	username, ok := userSessions.m[c.Value]
	userSessions.RUnlock()
	return username, ok
}

// =================== HANDLERS ===================
func homeHandler(w http.ResponseWriter, r *http.Request) {
	username, userLogged := isUser(r)
	data := map[string]interface{}{
		"title":       "Divisi SDM • Last Paradise",
		"year":        time.Now().Year(),
		"user":        username,
		"userLogged":  userLogged,
		"adminLogged": isAdmin(r),
	}
	render(w, "index_home.html", data)
}

func handbookHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title": "Handbook SDM - Last Paradise",
		"year":  time.Now().Year(),
	}
	render(w, "handbook.html", data)
}

// ------------------- ADMIN LOGIN -------------------
func loginChoiceHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title": "Pilih Login",
		"year":  time.Now().Year(),
	}
	render(w, "login.html", data)
}

func loginAdminHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "login.html", map[string]interface{}{
			"title": "Login Admin",
			"year":  time.Now().Year(),
		})
	case http.MethodPost:
		r.ParseForm()
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")

		if username != adminUsername || hashPassword(password) != adminPasswordHash {
			render(w, "login.html", map[string]interface{}{"error": "Username/password salah"})
			return
		}
		token := createToken()
		sessions.Lock()
		sessions.m[token] = username
		sessions.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "admin_token", Value: token, Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/list", http.StatusSeeOther)
	}
}

// ------------------- USER LOGIN -------------------
func loginUserHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "login.html", map[string]interface{}{"title": "Login User"})
	case http.MethodPost:
		r.ParseForm()
		username := r.FormValue("username")
		password := hashPassword(r.FormValue("password"))

		for _, u := range users {
			if u.Username == username && u.Password == password {
				token := createToken()
				userSessions.Lock()
				userSessions.m[token] = username
				userSessions.Unlock()
				http.SetCookie(w, &http.Cookie{Name: "user_token", Value: token, Path: "/", HttpOnly: true})
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
		}
		render(w, "login.html", map[string]interface{}{"error": "User tidak ditemukan"})
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin_token", Value: "", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "user_token", Value: "", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ------------------- USER REGISTER -------------------
func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		render(w, "register.html", map[string]interface{}{"title": "Daftar Akun"})
	case http.MethodPost:
		r.ParseForm()
		username := r.FormValue("username")
		password := hashPassword(r.FormValue("password"))

		for _, u := range users {
			if u.Username == username {
				render(w, "register.html", map[string]interface{}{"error": "Username sudah ada"})
				return
			}
		}

		newUser := User{Username: username, Password: password, Role: "user"}
		users = append(users, newUser)
		saveUsers()

		http.Redirect(w, r, "/login/user", http.StatusSeeOther)
	}
}

// ------------------- USER STATUS -------------------
func statusHandler(w http.ResponseWriter, r *http.Request) {
	username, _ := isUser(r)
	userRegs := []Registration{}
	for _, reg := range registrations {
		if reg.Username == username {
			userRegs = append(userRegs, reg)
		}
	}
	data := map[string]interface{}{
		"title": "Status Pendaftaran",
		"regs":  userRegs,
		"year":  time.Now().Year(),
	}
	render(w, "status.html", data)
}

// ------------------- ADMIN REGISTRATIONS -------------------
func adminRegistrationsHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title": "Admin - Pendaftaran",
		"regs":  registrations,
	}
	render(w, "registrations.html", data)
}

func updateRegistrationStatusHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))
	status := r.FormValue("status")

	for i, reg := range registrations {
		if reg.ID == id {
			registrations[i].Status = status
			break
		}
	}
	saveRegistrations()
	http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
}

// ================ PERSONNEL CRUD ================
func listHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"title":     "Daftar Personel",
		"personnel": readAll(),
		"year":      time.Now().Year(),
		"authed":    isAdmin(r),
	}
	render(w, "index.html", data)
}

func addFormHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{"title": "Tambah Personel"}
	render(w, "form.html", data)
}

func insertHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p := Personnel{ID: generateID(), Nama: r.FormValue("nama"), Jabatan: r.FormValue("jabatan"),
		Pangkat: r.FormValue("pangkat"), Foto: r.FormValue("foto"), Bio: r.FormValue("bio")}
	insert(p)
	savePersonnel()
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func editFormHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	p, ok := getByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{"title": "Edit Personel", "p": p}
	render(w, "edit.html", data)
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))
	p := Personnel{ID: id, Nama: r.FormValue("nama"), Jabatan: r.FormValue("jabatan"),
		Pangkat: r.FormValue("pangkat"), Foto: r.FormValue("foto"), Bio: r.FormValue("bio")}
	update(p)
	savePersonnel()
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	deleteByID(id)
	savePersonnel()
	http.Redirect(w, r, "/list", http.StatusSeeOther)
}

// ================ PERSONNEL LIST ================
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

// ================== FILE IO ==================
func savePersonnel() {
	data := readAll()
	b, _ := json.MarshalIndent(data, "", "  ")
	os.WriteFile(personnelFile, b, 0644)
}

func loadPersonnel() {
	if _, err := os.Stat(personnelFile); os.IsNotExist(err) {
		return
	}
	b, _ := os.ReadFile(personnelFile)
	var arr []Personnel
	json.Unmarshal(b, &arr)
	for _, p := range arr {
		insert(p)
		if p.ID > lastID {
			lastID = p.ID
		}
	}
}

func saveUsers() {
	b, _ := json.MarshalIndent(users, "", "  ")
	os.WriteFile(usersFile, b, 0644)
}

func loadUsers() {
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		return
	}
	b, _ := os.ReadFile(usersFile)
	json.Unmarshal(b, &users)
}

func saveRegistrations() {
	b, _ := json.MarshalIndent(registrations, "", "  ")
	os.WriteFile(registrationFile, b, 0644)
}

func loadRegistrations() {
	if _, err := os.Stat(registrationFile); os.IsNotExist(err) {
		return
	}
	b, _ := os.ReadFile(registrationFile)
	json.Unmarshal(b, &registrations)
	for _, r := range registrations {
		if r.ID > lastRegID {
			lastRegID = r.ID
		}
	}
}

func applyHandler(w http.ResponseWriter, r *http.Request) {
	username, _ := isUser(r)

	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{
			"title": "Pendaftaran SDM",
			"year":  time.Now().Year(),
		}
		render(w, "apply.html", data)

	case http.MethodPost:
		r.ParseForm()
		nama := r.FormValue("nama")
		pangkat := r.FormValue("pangkat")
		divisi := r.FormValue("divisi")
		q1 := r.FormValue("q1")
		q2 := r.FormValue("q2")
		q3 := r.FormValue("q3")
		q4 := r.FormValue("q4")

		lastRegID++
		reg := Registration{
			ID:       lastRegID,
			Username: username,
			Nama:     nama,
			Pangkat:  pangkat,
			Divisi:   divisi,
			Q1:       q1,
			Q2:       q2,
			Q3:       q3,
			Q4:       q4,
			Status:   "pending",
			Date:     time.Now(),
		}
		registrations = append(registrations, reg)
		saveRegistrations()

		http.Redirect(w, r, "/status", http.StatusSeeOther)
	}
}
