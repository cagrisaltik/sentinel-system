package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	// Ajanın ismini ortam değişkeninden al (Docker'dan vereceğiz)
	agentName := os.Getenv("AGENT_NAME")
	if agentName == "" {
		agentName = "Bilinmeyen-Asker"
	}

	fmt.Printf("🛡️ Sentinel Scout [%s] göreve başladı!\n", agentName)

	// Sonsuz döngü: Her 5 saniyede bir kalp atışı (heartbeat) gönder
	for {
		fmt.Printf("[%s] Scout [%s] rapor veriyor: Sistem aktif ve izlemede.\n",
			time.Now().Format("15:04:05"), agentName)

		time.Sleep(5 * time.Second)
	}
}
