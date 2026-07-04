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
	Conn      *websocket.Conn
	Username  string
	PublicKey string // Base64-encoded публичный ключ ECDH
}

var clients = make(map[*websocket.Conn]*Client)
var broadcast = make(chan Message, 10)
var mutex = &sync.Mutex{}
var db *sql.DB

type Message struct {
	Type             string   `json:"type"`
	Username         string   `json:"username"`
	Text             string   `json:"text"`
	Image            string   `json:"image,omitempty"`
	FileName         string   `json:"file_name,omitempty"`
	Payload          string   `json:"payload,omitempty"`
	Users            []string `json:"users,omitempty"`
	Receiver         string   `json:"receiver,omitempty"`
	GroupID          int      `json:"group_id,omitempty"`
	GroupName        string   `json:"group_name,omitempty"`
	PublicKey        string   `json:"public_key,omitempty"`
	EncryptedMessage string   `json:"encrypted_message,omitempty"`
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

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "messenger.db")
	if err != nil {
		panic(err)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, text TEXT, image TEXT, file_name TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS private_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, receiver TEXT, text TEXT, image TEXT, file_name TEXT, encrypted_message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, creator TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER, username TEXT, PRIMARY KEY (group_id, username))`)
	db.Exec(`CREATE TABLE IF NOT EXISTS group_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, username TEXT, text TEXT, image TEXT, file_name TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`)

	db.Exec("ALTER TABLE messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE group_messages ADD COLUMN image TEXT DEFAULT ''")
	db.Exec("ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE group_messages ADD COLUMN file_name TEXT DEFAULT ''")
	db.Exec("ALTER TABLE private_messages ADD COLUMN encrypted_message TEXT DEFAULT ''")
}

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
	rows, _ := db.Query("SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.username = ?", username)
	defer rows.Close()
	var groups []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		groups = append(groups, map[string]interface{}{"id": id, "name": name})
	}
	if err := rows.Err(); err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	json.NewEncoder(w).Encode(groups)
}

func availableGroupsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	rows, _ := db.Query("SELECT g.id, g.name FROM groups g WHERE g.id NOT IN (SELECT group_id FROM group_members WHERE username = ?)", username)
	defer rows.Close()
	var groups []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		rows.Scan(&id, &name)
		groups = append(groups, map[string]interface{}{"id": id, "name": name})
	}
	if err := rows.Err(); err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
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
	rows, _ := db.Query("SELECT username, text, image, file_name FROM group_messages WHERE group_id = ? ORDER BY timestamp DESC LIMIT 50", groupID)
	defer rows.Close()
	var history []map[string]interface{}
	for rows.Next() {
		var u, t, img, fn string
		rows.Scan(&u, &t, &img, &fn)
		history = append(history, map[string]interface{}{"username": u, "text": t, "image": img, "file_name": fn})
	}
	if err := rows.Err(); err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	json.NewEncoder(w).Encode(history)
}

// ==================== E2E КЛЮЧИ ====================

func registerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" || req.PublicKey == "" {
		json.NewEncoder(w).Encode(AuthResponse{Success: false, Message: "Missing fields"})
		return
	}
	// Сохраняем в памяти (для онлайн-пользователей)
	mutex.Lock()
	for _, client := range clients {
		if client.Username == req.Username {
			client.PublicKey = req.PublicKey
			break
		}
	}
	mutex.Unlock()
	json.NewEncoder(w).Encode(AuthResponse{Success: true})
}

func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"public_key": ""})
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	for _, client := range clients {
		if client.Username == username {
			json.NewEncoder(w).Encode(map[string]interface{}{"public_key": client.PublicKey})
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"public_key": ""})
}

// ==================== WEBSOCKET ====================

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

	// ИСПРАВЛЕНО: закрываем все старые соединения с этим username
	// Один аккаунт = одно устройство
	mutex.Lock()
	for oldConn, client := range clients {
		if client.Username == username {
			// Отправляем уведомление старому устройству
			oldConn.WriteJSON(Message{
				Type:     "system",
				Username: "Система",
				Text:     "Вы были отключены, так как вошли с другого устройства",
			})
			oldConn.Close()
			delete(clients, oldConn)
			console_log := "[INFO] Закрыто старое соединение для пользователя: " + username
			fmt.Println(console_log)
		}
	}
	mutex.Unlock()

	client := &Client{Conn: conn, Username: username, PublicKey: regMsg.PublicKey}

	mutex.Lock()
	clients[conn] = client
	mutex.Unlock()

	broadcast <- Message{Type: "system", Username: "Система", Text: username + " вошёл в чат"}
	sendUserList()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
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
		if msg.Type == "set_public_key" {
			mutex.Lock()
			if c, ok := clients[conn]; ok {
				c.PublicKey = msg.PublicKey
			}
			mutex.Unlock()
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
	if err := rows.Err(); err != nil {
		return
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

	type UserWithKey struct {
		Username  string `json:"username"`
		PublicKey string `json:"public_key"`
	}
	var usersWithKeys []UserWithKey
	for _, client := range clients {
		usersWithKeys = append(usersWithKeys, UserWithKey{
			Username:  client.Username,
			PublicKey: client.PublicKey,
		})
	}

	jsonData, _ := json.Marshal(map[string]interface{}{
		"type":  "user_list",
		"users": usersWithKeys,
	})

	for conn := range clients {
		conn.WriteMessage(websocket.TextMessage, jsonData)
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
	if err := rows.Err(); err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	json.NewEncoder(w).Encode(history)
}

func privateHistoryHandler(w http.ResponseWriter, r *http.Request) {
	user1 := r.URL.Query().Get("user1")
	user2 := r.URL.Query().Get("user2")
	rows, err := db.Query("SELECT sender, text, image, file_name, encrypted_message FROM private_messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) ORDER BY timestamp DESC LIMIT 50", user1, user2, user2, user1)
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
	if err := rows.Err(); err != nil {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
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

	// E2E Key endpoints
	http.HandleFunc("/keys/register", registerPublicKeyHandler)
	http.HandleFunc("/keys/get", getPublicKeyHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Сервер запущен на порту %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
