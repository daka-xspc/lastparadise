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
	"strconv"
	"sync"
	"time"
)

var (
	templates        = template.Must(template.ParseGlob("templates/*.html"))
	salt             = "lastparadise-sdm"
	personnelFile    = "data.json"
	registrationFile = "registrations.json"
	usersFile        = "users.json"
	personnel        = []Personnel{}
	registrations    = []Registration{}
	users            = []User{}
	lastRegID        int
	lastID           = 0
	muPersonnel      sync.Mutex
	muRegistrations  sync.Mutex
	muUsers          sync.Mutex
	personnelList    = &listPersonnel{}
)

// Define role hierarchy
var roleHierarchy = map[string]int{
	"user":             1,
	"admin":            2,
	"forum_management": 3,
	"super_admin":      4,
}

// --- SESSION HANDLING ---
var sessions = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

var sessionRoles = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// --- STRUCTS ---
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // user, admin, forum_management, super_admin
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
	Status   string    `json:"status"`
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

// --- FILE IO ---
func loadData() {
	loadPersonnel()
	loadRegistrations()
	loadUsers()
}

func savePersonnel() {
	b, _ := json.MarshalIndent(personnel, "", "  ")
	os.WriteFile(personnelFile, b, 0644)
}

func loadPersonnel() {
	muPersonnel.Lock()
	defer muPersonnel.Unlock()
	if _, err := os.Stat(personnelFile); os.IsNotExist(err) {
		return
	}
	b, _ := os.ReadFile(personnelFile)
	json.Unmarshal(b, &personnel)
	for _, p := range personnel {
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
	muUsers.Lock()
	defer muUsers.Unlock()
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
	muRegistrations.Lock()
	defer muRegistrations.Unlock()
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

func appendUserToFile(user User) error {
	muUsers.Lock()
	defer muUsers.Unlock()

	var existingUsers []User
	file, err := os.Open(usersFile)
	if err == nil {
		defer file.Close()
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&existingUsers); err != nil && err.Error() != "EOF" {
			return fmt.Errorf("failed to decode users file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to open users file: %w", err)
	}

	existingUsers = append(existingUsers, user)

	b, err := json.MarshalIndent(existingUsers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal users: %w", err)
	}
	return os.WriteFile(usersFile, b, 0644)
}

// --- TEMPLATE & AUTH ---
func render(w http.ResponseWriter, tmpl string, data interface{}) {
	templates.ExecuteTemplate(w, tmpl, data)
}

func getSessionInfo(r *http.Request) (string, string) {
	c, err := r.Cookie("session_token")
	if err != nil {
		return "", ""
	}
	sessions.RLock()
	username, ok := sessions.m[c.Value]
	sessions.RUnlock()
	if !ok {
		return "", ""
	}
	sessionRoles.RLock()
	role, ok := sessionRoles.m[username]
	sessionRoles.RUnlock()
	if !ok {
		return username, "user"
	}
	return username, role
}

func checkAuth(w http.ResponseWriter, r *http.Request, requiredRole string) bool {
	c, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	sessions.RLock()
	username, ok := sessions.m[c.Value]
	sessions.RUnlock()
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}

	sessionRoles.RLock()
	userRole, ok := sessionRoles.m[username]
	sessionRoles.RUnlock()
	if !ok {
		userRole = "user"
	}

	requiredRank, ok := roleHierarchy[requiredRole]
	if !ok {
		http.Error(w, "Invalid role configuration", http.StatusInternalServerError)
		return false
	}
	userRank, ok := roleHierarchy[userRole]
	if !ok {
		http.Error(w, "Invalid user role", http.StatusInternalServerError)
		return false
	}

	if userRank < requiredRank {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return false
	}
	return true
}

// --- UTILS ---
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(h[:])
}

func createSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// --- HANDLERS ---
// Diganti dengan versi yang sudah diperbarui dan benar
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	username, role := getSessionInfo(r)

	data := map[string]interface{}{
		"title":       "Portal Divisi SDM",
		"user":        username,
		"role":        role,
		"userLogged":  username != "",
		"adminLogged": roleHierarchy[role] >= roleHierarchy["admin"],
		"year":        time.Now().Year(),
	}
	render(w, "index_home.html", data)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	_, role := getSessionInfo(r)
	data := map[string]interface{}{
		"title":     "Daftar Personel",
		"personnel": readAll(),
		"authed":    role != "",
	}
	render(w, "index.html", data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{"title": "Login"}
		render(w, "login.html", data)
	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		var userRole string
		found := false
		muUsers.Lock()
		for _, u := range users {
			if u.Username == username && u.Password == hashPassword(password) {
				userRole = u.Role
				found = true
				break
			}
		}
		muUsers.Unlock()

		if !found {
			data := map[string]interface{}{
				"title": "Login",
				"error": "Username atau password salah",
			}
			render(w, "login.html", data)
			return
		}

		token := createSessionToken()
		sessions.Lock()
		sessions.m[token] = username
		sessions.Unlock()
		sessionRoles.Lock()
		sessionRoles.m[username] = userRole
		sessionRoles.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   3600,
		})

		http.Redirect(w, r, "/list", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{"title": "Daftar Akun"}
		render(w, "register.html", data)
	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		muUsers.Lock()
		for _, u := range users {
			if u.Username == username {
				muUsers.Unlock()
				data := map[string]interface{}{
					"title": "Daftar Akun",
					"error": "Username sudah ada",
				}
				render(w, "register.html", data)
				return
			}
		}

		newUser := User{Username: username, Password: hashPassword(password), Role: "user"}
		users = append(users, newUser)
		saveUsers()
		muUsers.Unlock()

		http.Redirect(w, r, "/login", http.StatusSeeOther)
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

func registrationsHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r, "admin") {
		return
	}
	_, role := getSessionInfo(r)

	data := map[string]interface{}{
		"title":             "Admin Panel - Registrasi",
		"registrations":     registrations,
		"IsAdmin":           roleHierarchy[role] >= roleHierarchy["admin"],
		"IsForumManagement": roleHierarchy[role] >= roleHierarchy["forum_management"],
		"IsSuperAdmin":      roleHierarchy[role] >= roleHierarchy["super_admin"],
	}
	render(w, "registrations.html", data)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	username, _ := getSessionInfo(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	muRegistrations.Lock()
	defer muRegistrations.Unlock()

	userRegs := []Registration{}
	for _, reg := range registrations {
		if reg.Username == username {
			userRegs = append(userRegs, reg)
		}
	}
	data := map[string]interface{}{
		"title": "Status Pendaftaran",
		"regs":  userRegs,
	}
	render(w, "status.html", data)
}

func setStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r, "admin") {
		return
	}
	r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))
	status := r.FormValue("status")

	muRegistrations.Lock()
	defer muRegistrations.Unlock()
	for i, reg := range registrations {
		if reg.ID == id {
			registrations[i].Status = status
			saveRegistrations()
			http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
			return
		}
	}
	http.NotFound(w, r)
}

func deleteRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r, "forum_management") {
		return
	}
	r.ParseForm()
	id, _ := strconv.Atoi(r.FormValue("id"))

	muRegistrations.Lock()
	defer muRegistrations.Unlock()
	for i, reg := range registrations {
		if reg.ID == id {
			registrations = append(registrations[:i], registrations[i+1:]...)
			saveRegistrations()
			http.Redirect(w, r, "/admin/registrations", http.StatusSeeOther)
			return
		}
	}
	http.NotFound(w, r)
}

func userManagementHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r, "forum_management") {
		return
	}
	_, role := getSessionInfo(r)

	data := map[string]interface{}{
		"title":             "Manajemen Pengguna",
		"users":             users,
		"IsForumManagement": roleHierarchy[role] >= roleHierarchy["forum_management"],
		"IsSuperAdmin":      roleHierarchy[role] >= roleHierarchy["super_admin"],
	}
	render(w, "user_management.html", data)
}

func setUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r, "super_admin") {
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	newRole := r.FormValue("role")

	muUsers.Lock()
	defer muUsers.Unlock()
	for i, u := range users {
		if u.Username == username {
			users[i].Role = newRole
			saveUsers()
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			return
		}
	}
	http.NotFound(w, r)
}

func applyHandler(w http.ResponseWriter, r *http.Request) {
	username, _ := getSessionInfo(r)
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	muRegistrations.Lock()
	defer muRegistrations.Unlock()
	for _, reg := range registrations {
		if reg.Username == username {
			data := map[string]interface{}{"title": "Pendaftaran SDM", "error": "Pendaftaran Anda sudah ada. Silakan periksa status Anda."}
			render(w, "apply.html", data)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{
			"title": "Pendaftaran SDM",
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
		newReg := Registration{
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
		registrations = append(registrations, newReg)
		saveRegistrations()

		data := map[string]interface{}{
			"title":   "Pendaftaran SDM",
			"success": "Pendaftaran Anda berhasil. Silakan tunggu konfirmasi dari Admin.",
		}
		render(w, "apply.html", data)
	}
}

func main() {
	loadData()

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler) // homeHandler sekarang adalah homeIndexHandler yang sudah diperbaiki
	mux.HandleFunc("/list", listHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/apply", applyHandler)
	mux.HandleFunc("/status", statusHandler)
	mux.HandleFunc("/admin/registrations", registrationsHandler)
	mux.HandleFunc("/admin/setstatus", setStatusHandler)
	mux.HandleFunc("/admin/delete", deleteRegistrationHandler)
	mux.HandleFunc("/admin/users", userManagementHandler)
	mux.HandleFunc("/admin/setrole", setUserRoleHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/handbook", func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{"title": "Handbook SDM", "content": "Konten handbook akan diletakkan di sini."}
		render(w, "handbook.html", data)
	})
	log.Println("Server berjalan di http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}

// Fungsi-fungsi lain (generateID, insert, readAll, getByID, update, deleteByID, saveData)
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
	return os.WriteFile(personnelFile, b, 0644)
}

func loadPersonnelData() error {
	if _, err := os.Stat(personnelFile); os.IsNotExist(err) {
		return nil
	}
	b, err := os.ReadFile(personnelFile)
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
