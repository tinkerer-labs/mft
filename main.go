package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/tinkerer-labs/mft/internal/network"
)

func main() {
	sessionName := flag.String("name", "MonP2P_Default", "Nom de la session I2P (Unique par instance)")
	flag.Parse()

	fmt.Printf("Demarrage de l'instance : %s\n", *sessionName)

	// 1. Demarrer le Noeud I2P
	node, err := network.NewI2PNode("127.0.0.1:7656", *sessionName)
	if err != nil {
		log.Fatal(err)
	}

	defer node.Close()

	fmt.Println("------------------------------------------------")
	fmt.Println("🚀 MON ADRESSE I2P (Partage-la avec ton ami) :")
	fmt.Println(node.Address)
	fmt.Println("------------------------------------------------")

	// 2. Lancer le serveur d'ecoute (Routine Goroutine)
	go func() {
		for {
			// Accepter une nouvelle connexion entrante (comme du TCP classique)
			conn, err := node.Listener.Accept()
			if err != nil {
				log.Printf("Erreur accept: %v", err)
				continue
			}

			// Gerer la connexion
			go func(c net.Conn) {
				defer c.Close()

				// Recuperation de l'adresse de celui qui nous parle
				remoteAddr := c.RemoteAddr().String()

				reader := bufio.NewReader(c)
				msg, err := reader.ReadString('\n')
				if err != nil {
					log.Printf("erreur readstring: %v", err)
					return
				}

				// Afficher l'adresse de l'expéditeur + le message
				fmt.Printf("\n------------------------------------------------")
				fmt.Printf("\n📩 MESSAGE REÇU DE :\n%s\n", remoteAddr) // <--- ICI
				fmt.Printf("CONTENU : %s", msg)
				fmt.Printf("------------------------------------------------\n> ")
			}(conn)
		}
	}()

	// 3. Interface pour envoyer des messages (Gossip manuel)
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Entre une adresse I2P de destination pour envoyer un message : ")

	// on lit l'adresse cible une fois
	scanner.Scan()
	target := strings.TrimSpace(scanner.Text())

	fmt.Println("Tu peux maintenant taper des messages. Ils passeront par I2P !")
	fmt.Println("> ")

	for scanner.Scan() {
		msg := scanner.Text()

		// Connexion sortante vers la cible
		conn, err := node.Dial(target)
		if err != nil {
			log.Printf("Impossible de joindre le pair: %v", err)
			continue
		}

		// envoi du message
		fmt.Fprintf(conn, "%s\n", msg)
		conn.Close() // on ferme juste apres (pour l'exemple)
		fmt.Print("> ")
	}
}
