package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/vultisig/vultiserver/relay"
)

// WaitForPartiesToJoin waits for the expected number of parties to join a session
func WaitForPartiesToJoin(sessionID, relayServer, localParty string, expectedParties int, timeout time.Duration) ([]string, error) {
	relayClient := relay.NewRelayClient(relayServer)

	// Register ourselves with the relay
	if err := relayClient.RegisterSession(sessionID, localParty); err != nil {
		return nil, fmt.Errorf("failed to register with relay: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for ctx.Err() == nil {
		partiesJoined, err := relayClient.GetSession(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get session status: %w", err)
		}

		fmt.Printf("Parties joined (%d/%d): %v\n", len(partiesJoined), expectedParties, partiesJoined)

		if len(partiesJoined) == expectedParties {
			// All parties joined, start the session
			if err := relayClient.StartSession(sessionID, partiesJoined); err != nil {
				return nil, fmt.Errorf("failed to start session: %w", err)
			}

			fmt.Printf("✓ Started session with %d parties\n", len(partiesJoined))
			return partiesJoined, nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for all parties to join")
}

// GetKeygenThreshold calculates the threshold for the given number of signers
func GetKeygenThreshold(signers int) int {
	// This follows the formula: Math.ceil((signers * 2) / 3) from vultisig-windows
	// For 2 signers: ceil((2 * 2) / 3) = ceil(4/3) = ceil(1.33) = 2
	// For 2-of-2 fast vault, we use threshold = 2
	if signers == 2 {
		return 2
	}
	return (signers*2 + 2) / 3 // Integer ceiling division
}