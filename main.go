package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Client struct {
	Conn     *websocket.Conn
	Username string
}

var clients = make(map[*websocket.Conn]*Client)
var broadcast = make(chan Message, 10)
var mutex = &sync.Mutex{}
var db *sql.DB

type Message struct {
	Type        string   `json:"type"`
	Username    string   `json:"username"`
	Text        string   `json:"text"`
	Image       string   `json:"image,omitempty"`
	FileName    string   `json:"file_name,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	Users       []string `json:"users,omitempty"`
	Receiver    string   `json:"receiver,omitempty"`
	GroupID     int      `json:"group_id,omitempty"`
	GroupName   string   `json:"group_name,omitempty"`
	// Signal Protocol fields
	EncryptedMessage string `json:"encrypted_message,omitempty"`
	PreKeyBundle     string `json:"pre_key_bundle,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type GroupRequest struct {
	Name     string `json:"name"`
	Creator  string `json:"creator"`
	GroupID  int    `json:"group_id"`
	Username string `json:"username"`
}

// Signal Protocol structures
type IdentityKeyRequest struct {
	Username       string `json:"username"`
	IdentityKey    string `json:"identity_key"`
	RegistrationID int    `json:"registration_id"`
}

type PreKeyRequest struct {
	Username string `json:"username"`
	KeyID    int    `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type OneTimePreKeyRequest struct {
	Username  string `json:"username"`
	KeyID     int    `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type PreKeyBundleResponse struct {
	IdentityKey    string `json:"identity_key"`
	RegistrationID int    `json:"registration_id"`
	SignedPreKeyID int    `json:"signed_pre_key_id"`
	SignedPreKey   string `json:"signed_pre_key"`
	Signature      string `json:"signature"`
	PreKeyID       int    `json:"pre_key_id"`
	PreKey         string `json:"pre_key"`
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "messenger.db")
	if err != nil {
		panic(err)
	}

	// Existing tables
	db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, text TEXT, image TEXT, file_name TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS private_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, text TEXT, image TEXT, file_name TEXT, encrypted_message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, creator TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER, username TEXT, PRIMARY KEY (group_id, username))`)
	db.Exec(`CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, username TEXT, text TEXT, image TEXT, file_name TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)

	// Signal Protocol tables
	db.Exec(`CREATE TABLE IF NOT EXISTS identity_keys (username TEXT PRIMARY KEY, identity_key TEXT NOT NULL, registration_id INTEGER NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS signed_prekeys (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, key_id INTEGER NOT NULL, public_key TEXT NOT NULL, signature TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(username, key_id))`)
	db.Exec(`CREATE TABLE IF NOT EXISTS one_time_prekeys (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, key_id INTEGER NOT NULL, public_key TEXT NOT NULL, used INTEGER DEFAULT 0, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(username, key_id))`)
	db.Exec(`CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, recipient TEXT NOT NULL, session_record TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(username, recipient))`)

	// Migrations
	db.Exec("ALTER TABLE messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE group_messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE group_messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN encrypted_message TEXT DEFAULT ''")
}

// Signal Protocol API endpoints

func registerIdentityKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req IdentityKeyRequest
	json.NewDecoder(r.Body).Decode(&req)
	
	if req.Username == "" || req.IdentityKey == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing fields"})
		return
	}

	_, err := db.Exec(
		"INSERT OR REPLACE INTO identity_keys (username, identity_key, registration_id) VALUES (?, ?, ?)",
		req.Username, req.IdentityKey, req.RegistrationID,
	)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to register identity key"})
		return
	}

	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func registerSignedPreKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req PreKeyRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Username == "" || req.PublicKey == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing fields"})
		return
	}

	_, err := db.Exec(
		"INSERT OR REPLACE INTO signed_prekeys (username, key_id, public_key, signature) VALUES (?, ?, ?, ?)",
		req.Username, req.KeyID, req.PublicKey, req.Signature,
	)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to register signed prekey"})
		return
	}

	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func registerOneTimePreKeysHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string             `json:"username"`
		PreKeys  []OneTimePreKeyRequest `json:"pre_keys"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Username == "" || len(req.PreKeys) == 0 {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing fields"})
		return
	}

	for _, pk := range req.PreKeys {
		_, err := db.Exec(
			"INSERT OR IGNORE INTO one_time_prekeys (username, key_id, public_key) VALUES (?, ?, ?)",
			req.Username, pk.KeyID, pk.PublicKey,
		)
		if err != nil {
			json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to register one-time prekey"})
			return
		}
	}

	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func getPreKeyBundleHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing username"})
		return
	}

	// Get identity key
	var identityKey string
	var registrationID int
	err := db.QueryRow("SELECT identity_key, registration_id FROM identity_keys WHERE username = ?", username).Scan(&identityKey, &registrationID)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "User not found"})
		return
	}

	// Get signed prekey
	var signedPreKeyID int
	var signedPreKey, signature string
	err = db.QueryRow("SELECT key_id, public_key, signature FROM signed_prekeys WHERE username = ? ORDER BY timestamp DESC LIMIT 1", username).Scan(&signedPreKeyID, &signedPreKey, &signature)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "No signed prekey"})
		return
	}

	// Get one-time prekey
	var preKeyID int
	var preKey string
	err = db.QueryRow("SELECT id, public_key FROM one_time_prekeys WHERE username = ? AND used = 0 ORDER BY id LIMIT 1", username).Scan(&preKeyID, &preKey)
	if err != nil {
		// No one-time prekeys available, return bundle without it
		response := PreKeyBundleResponse{
			IdentityKey:    identityKey,
			RegistrationID: registrationID,
			SignedPreKeyID: signedPreKeyID,
			SignedPreKey:   signedPreKey,
			Signature:      signature,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// Mark prekey as used
	db.Exec("UPDATE one_time_prekeys SET used = 1 WHERE id = ?", preKeyID)

	response := PreKeyBundleResponse{
		IdentityKey:    identityKey,
		RegistrationID: registrationID,
		SignedPreKeyID: signedPreKeyID,
		SignedPreKey:   signedPreKey,
		Signature:      signature,
		PreKeyID:       preKeyID,
		PreKey:         preKey,
	}

	json.NewEncoder(w).Encode(response)
}

func saveSessionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username      string `json:"username"`
		Recipient     string `json:"recipient"`
		SessionRecord string `json:"session_record"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Username == "" || req.Recipient == "" || req.SessionRecord == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing fields"})
		return
	}

	_, err := db.Exec(
		"INSERT OR REPLACE INTO sessions (username, recipient, session_record) VALUES (?, ?, ?)",
		req.Username, req.Recipient, req.SessionRecord,
	)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Failed to save session"})
		return
	}

	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func getSessionHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	recipient := r.URL.Query().Get("recipient")

	if username == "" || recipient == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing parameters"})
		return
	}

	var sessionRecord string
	err := db.QueryRow("SELECT session_record FROM sessions WHERE username = ? AND recipient = ?", username, recipient).Scan(&sessionRecord)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"session": nil})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"session": sessionRecord})
}

// Existing handlers (unchanged)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" || req.Password == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Заполните все поля"})
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if count > 0 {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Пользователь уже существует"})
		return
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, string(hashedPassword))
	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req AuthRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" || req.Password == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Заполните все поля"})
		return
	}
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&hashedPassword)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Неверное имя или пароль"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Неверное имя или пароль"})
		return
	}
	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func createGroupHandler(w http.ResponseWriter, r *http.Request) {
	var req GroupRequest
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name == "" || req.Creator == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Заполните все поля"})
		return
	}
	var count int
	db.QueryRow("SELECT COUNT(*) FROM groups WHERE name = ?", req.Name).Scan(&count)
	if count > 0 {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Группа уже существует"})
		return
	}
	result, _ := db.Exec("INSERT INTO groups (name, creator) VALUES (?, ?)", req.Name, req.Creator)
	groupID, _ := result.LastInsertId()
	db.Exec("INSERT INTO group_members (group_id, username) VALUES (?, ?)", groupID, req.Creator)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "group_id": groupID})
}

func groupsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	rows, _ := db.Query(`SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?`, username)
	defer rows.Close()
	var groups []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		groups = append(groups, map[string]interface{}{"id": id, "name": name})
	}
	json.NewEncoder(w).Encode(groups)
}

func availableGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	rows, _ := db.Query(`SELECT g.id, g.name FROM groups g WHERE g.id NOT IN (SELECT group_id FROM group_members WHERE username = ?)`, username)
	defer rows.Close()
	var groups []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		groups = append(groups, map[string]interface{}{"id": id, "name": name})
	}
	json.NewEncoder(w).Encode(groups)
}

func joinGroupHandler(w http.ResponseWriter, r *http.Request) {
	var req GroupRequest
	json.NewDecoder(r.Body).Decode(&req)
	_, err := db.Exec("INSERT INTO group_members (group_id, username) VALUES (?, ?)", req.GroupID, req.Username)
	if err != nil {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Ошибка вступления"})
		return
	}
	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func groupHistoryHandler(w http.ResponseWriter, r *http.Request) {
	groupID := r.URL.Query().Get("group_id")
	rows, _ := db.Query(`SELECT username, text, image, file_name FROM group_messages WHERE group_id = ? ORDER BY timestamp DESC LIMIT 50`, groupID)
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var u, t, img, fn string
		rows.Scan(&u, &t, &img, &fn)
		history = append(history, map[string]interface{}{"username": u, "text": t, "image": img, "file_name": fn})
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	json.NewEncoder(w).Encode(history)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	var regMsg Message
	if conn.ReadJSON(&regMsg) != nil || regMsg.Type != "register" {
		return
	}

	username := regMsg.Username
	client := &Client{Conn: conn, Username: username}

	mutex.Lock()
	clients[conn] = client
	mutex.Unlock()

	broadcast <- Message{Type: "system", Username: "Система", Text: username + " вошёл в чат"}
	sendUserList()

	for {
		var msg Message
		if conn.ReadJSON(&msg) != nil {
			mutex.Lock()
			delete(clients, conn)
			mutex.Unlock()
			broadcast <- Message{Type: "system", Username: "Система", Text: username + " вышел из чата"}
			sendUserList()
			break
		}
		msg.Username = username

		if msg.Type == "typing" {
			handleTyping(msg)
			continue
		}
		if msg.Type == "webrtc" && msg.Receiver != "" {
			handleWebRTC(msg)
			continue
		}
		if msg.Type == "group_message" && msg.GroupID != 0 {
			db.Exec("INSERT INTO group_messages (group_id, username, text, image, file_name) VALUES (?, ?, ?, ?, ?)", msg.GroupID, username, msg.Text, msg.Image, msg.FileName)
			handleGroupMessage(msg)
		} else if msg.Type == "private" && msg.Receiver != "" {
			db.Exec("INSERT INTO private_messages (sender, receiver, text, image, file_name, encrypted_message) VALUES (?, ?, ?, ?, ?, ?)",
				username, msg.Receiver, msg.Text, msg.Image, msg.FileName, msg.EncryptedMessage)
			handlePrivateMessage(msg)
		} else {
			db.Exec("INSERT INTO messages (username, text, image, file_name) VALUES (?, ?, ?, ?)", username, msg.Text, msg.Image, msg.FileName)
			msg.Type = "message"
			broadcast <- msg
		}
	}
}

func handleWebRTC(msg Message) {
	mutex.Lock()
	defer mutex.Unlock()
	for conn, client := range clients {
		if client.Username == msg.Receiver {
			conn.WriteJSON(msg)
			return
		}
	}
}

func handleTyping(msg Message) {
	mutex.Lock()
	defer mutex.Unlock()
	for conn, client := range clients {
		if client.Username != msg.Username {
			conn.WriteJSON(msg)
		}
	}
}

func handlePrivateMessage(msg Message) {
	mutex.Lock()
	defer mutex.Unlock()
	for conn, client := range clients {
		if client.Username == msg.Receiver || client.Username == msg.Username {
			conn.WriteJSON(msg)
		}
	}
}

func handleGroupMessage(msg Message) {
	mutex.Lock()
	defer mutex.Unlock()
	rows, _ := db.Query("SELECT username FROM group_members WHERE group_id = ?", msg.GroupID)
	defer rows.Close()
	var members []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		members = append(members, u)
	}
	for conn, client := range clients {
		for _, member := range members {
			if client.Username == member {
				conn.WriteJSON(msg)
				break
			}
		}
	}
}

func sendUserList() {
	mutex.Lock()
	defer mutex.Unlock()
	var users []string
	for _, client := range clients {
		users = append(users, client.Username)
	}
	msg := Message{Type: "user_list", Users: users}
	for conn := range clients {
		conn.WriteJSON(msg)
	}
}

func handleMessages() {
	for {
		msg := <-broadcast
		mutex.Lock()
		for conn := range clients {
			if err := conn.WriteJSON(msg); err != nil {
				conn.Close()
				delete(clients, conn)
			}
		}
		mutex.Unlock()
	}
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT username, text, image, file_name FROM messages ORDER BY timestamp DESC LIMIT 50")
	if err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var u, t, img, fn string
		rows.Scan(&u, &t, &img, &fn)
		history = append(history, map[string]interface{}{"username": u, "text": t, "image": img, "file_name": fn})
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	json.NewEncoder(w).Encode(history)
}

func privateHistoryHandler(w http.ResponseWriter, r *http.Request) {
	user1 := r.URL.Query().Get("user1")
	user2 := r.URL.Query().Get("user2")
	rows, err := db.Query(`SELECT sender, text, image, file_name, encrypted_message FROM private_messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) ORDER BY timestamp DESC LIMIT 50`, user1, user2, user2, user1)
	if err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var s, t, img, fn, enc string
		rows.Scan(&s, &t, &img, &fn, &enc)
		history = append(history, map[string]interface{}{
			"sender": s, "text": t, "image": img, "file_name": fn, "encrypted_message": enc,
		})
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	json.NewEncoder(w).Encode(history)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func main() {
	initDB()
	go handleMessages()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/history", historyHandler)
	http.HandleFunc("/private_history", privateHistoryHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/create_group", createGroupHandler)
	http.HandleFunc("/groups", groupsHandler)
	http.HandleFunc("/available_groups", availableGroupsHandler)
	http.HandleFunc("/join_group", joinGroupHandler)
	http.HandleFunc("/group_history", groupHistoryHandler)
	
	// Signal Protocol endpoints
	http.HandleFunc("/signal/register_identity", registerIdentityKeyHandler)
	http.HandleFunc("/signal/register_signed_prekey", registerSignedPreKeyHandler)
	http.HandleFunc("/signal/register_one_time_prekeys", registerOneTimePreKeysHandler)
	http.HandleFunc("/signal/get_prekey_bundle", getPreKeyBundleHandler)
	http.HandleFunc("/signal/save_session", saveSessionHandler)
	http.HandleFunc("/signal/get_session", getSessionHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Сервер запущен на порту %s\n", port)
	http.ListenAndServe(":"+port, nil)
}