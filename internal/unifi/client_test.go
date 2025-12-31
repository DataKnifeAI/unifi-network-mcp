package unifi

import (
	"testing"
)

func TestProtectClientCreation(t *testing.T) {
	client := NewProtectClient("https://localhost:7443", "test-api-key", false)
	if client == nil {
		t.Fatal("Failed to create ProtectClient")
	}
	if client.baseURL != "https://localhost:7443" {
		t.Errorf("Expected baseURL to be set, got %s", client.baseURL)
	}
}

func TestNetworkClientCreation(t *testing.T) {
	client := NewNetworkClient("https://localhost:8443", "test-api-key", false)
	if client == nil {
		t.Fatal("Failed to create NetworkClient")
	}
	if client.baseURL != "https://localhost:8443" {
		t.Errorf("Expected baseURL to be set, got %s", client.baseURL)
	}
}
