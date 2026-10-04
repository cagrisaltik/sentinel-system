package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cagrisaltik/sentinel-system/internal/models"
	"github.com/gorilla/websocket"
)

func newScoutWebSocketTestConn(t *testing.T, handler func(*websocket.Conn)) *websocket.Conn {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer peer.Close()
		handler(peer)
	}))
	t.Cleanup(server.Close)

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial test WebSocket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestScoutReadLimitRejectsOversizedMessage(t *testing.T) {
	conn := newScoutWebSocketTestConn(t, func(peer *websocket.Conn) {
		payload := strings.Repeat("x", maxMessageSize+1)
		_ = peer.WriteMessage(websocket.TextMessage, []byte(payload))
	})
	if err := configureScoutWebSocket(conn, time.Second); err != nil {
		t.Fatalf("configure Scout WebSocket: %v", err)
	}

	var msg models.Command
	err := conn.ReadJSON(&msg)
	if !errors.Is(err, websocket.ErrReadLimit) {
		t.Fatalf("oversized message error = %v, want ErrReadLimit", err)
	}
}

func TestScoutPongRenewsReadDeadline(t *testing.T) {
	conn := newScoutWebSocketTestConn(t, func(peer *websocket.Conn) {
		time.Sleep(150 * time.Millisecond)
		if err := peer.WriteControl(websocket.PongMessage, []byte("pong"), time.Now().Add(time.Second)); err != nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
		_ = peer.WriteJSON(models.Command{Type: "PING_REQUEST"})
	})
	if err := configureScoutWebSocket(conn, 400*time.Millisecond); err != nil {
		t.Fatalf("configure Scout WebSocket: %v", err)
	}

	var msg models.Command
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read after Pong-renewed deadline: %v", err)
	}
	if msg.Type != "PING_REQUEST" {
		t.Fatalf("message type = %q, want PING_REQUEST", msg.Type)
	}
}

func TestScoutControlPingKeepsDefaultPongBehavior(t *testing.T) {
	pongReceived := make(chan struct{})
	conn := newScoutWebSocketTestConn(t, func(peer *websocket.Conn) {
		peer.SetPongHandler(func(string) error {
			select {
			case <-pongReceived:
			default:
				close(pongReceived)
			}
			return nil
		})
		go func() { _, _, _ = peer.ReadMessage() }()

		time.Sleep(150 * time.Millisecond)
		if err := peer.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(time.Second)); err != nil {
			return
		}
		select {
		case <-pongReceived:
		case <-time.After(time.Second):
			return
		}
		time.Sleep(300 * time.Millisecond)
		_ = peer.WriteJSON(models.Command{Type: "PING_REQUEST"})
	})
	if err := configureScoutWebSocket(conn, 400*time.Millisecond); err != nil {
		t.Fatalf("configure Scout WebSocket: %v", err)
	}

	var msg models.Command
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read after control Ping: %v", err)
	}
	select {
	case <-pongReceived:
	default:
		t.Fatal("Scout did not send the default control Pong")
	}
}
