package network

import (
	"fmt"
	"log"
	"net"

	"github.com/go-i2p/sam3"
)

type I2PNode struct {
	samSession *sam3.StreamSession
	Listener   *sam3.StreamListener
	Address    string
}

func NewI2PNode(samAddr, sessionName string) (*I2PNode, error) {
	// 1. Connexion au pont SAM (generalement 127.0.0.1:7656)
	sam, err := sam3.NewSAM(samAddr)
	if err != nil {
		return nil, fmt.Errorf("erreur connexion SAM: %w (i2pd est-il lancé ?)", err)
	}

	log.Println("✅ Connecté au pont SAM")

	// 2. Creation des cles (Identite persistante)
	// Si les cles existent deja pour ce "sessionName", sam3 les reutilise.
	keys, err := sam.NewKeys()
	if err != nil {
		return nil, fmt.Errorf("erreur génération clés: %w", err)
	}

	// 3. Création de la Session de Stream (TCP-like)
	streamSession, err := sam.NewStreamSession(sessionName, keys, sam3.Options_Default)
	if err != nil {
		return nil, fmt.Errorf("erreur creation session: %w", err)
	}

	log.Printf("✅ Session I2P ouverte. Mon adresse : %s", keys.Addr().Base32())

	// 4. Creation du Listener (pour ecouter les connexions entrantes)
	listener, err := streamSession.Listen()
	if err != nil {
		return nil, fmt.Errorf("erreur listener: %w", err)
	}

	return &I2PNode{
		samSession: streamSession,
		Listener:   listener,
		Address:    keys.Address.Base32(),
	}, nil
}

// Dial permet de se connecter a un autre pair I2P
func (n *I2PNode) Dial(targetI2PAddr string) (net.Conn, error) {
	log.Printf("Tentative de connexion vers %s...", targetI2PAddr)
	conn, err := n.samSession.Dial("i2p", targetI2PAddr)
	if err != nil {
		return nil, err
	}
	return conn, err
}

// Close ferme tout proprement
func (n *I2PNode) Close() {
	n.Listener.Close()
	n.samSession.Close()
}
