package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
	"github.com/surrealwolf/unifi-network-mcp/internal/unifi"
)

// Server represents the MCP server
type Server struct {
	networkClient *unifi.NetworkClient
	server        *server.MCPServer
	logger        *logrus.Entry
}

// NewServer creates a new MCP server
func NewServer(networkClient *unifi.NetworkClient) *Server {
	s := &Server{
		networkClient: networkClient,
		server:        server.NewMCPServer("unifi-network-mcp", "0.1.0"),
		logger:        logrus.WithField("component", "MCPServer"),
	}

	s.registerTools()
	return s
}

// resolveSiteID resolves a site identifier (name or ID) to the site external ID (UUID) for API v1 calls.
// If siteID is empty or "default", it returns the first site's external ID.
// Otherwise, it tries to find a site by name or ID and returns its external ID.
func (s *Server) resolveSiteID(ctx context.Context, siteID string) (string, error) {
	// Fetch sites to get the correct external ID
	sites, err := s.networkClient.GetSites(ctx)
	if err != nil {
		return "", err
	}

	if len(sites) == 0 {
		return "", fmt.Errorf("no sites available")
	}

	// If empty or "default", return the first site's external ID (UUID)
	if siteID == "" || siteID == "default" {
		return sites[0].ExternalID, nil
	}

	// Try to find by name first
	for _, site := range sites {
		if site.Name == siteID {
			return site.ExternalID, nil
		}
	}

	// Try to find by ID (either _id or external_id)
	for _, site := range sites {
		if site.ID == siteID || site.ExternalID == siteID {
			return site.ExternalID, nil
		}
	}

	// If not found, assume it's already a site external ID (UUID) and return it
	return siteID, nil
}

func (s *Server) registerTools() {
	tools := []server.ServerTool{}

	// Helper to create tool definitions
	addTool := func(name, desc string, handler server.ToolHandlerFunc, properties map[string]any) {
		tools = append(tools, server.ServerTool{
			Tool: mcp.Tool{
				Name:        name,
				Description: desc,
				InputSchema: mcp.ToolInputSchema{
					Type:       "object",
					Properties: properties,
				},
			},
			Handler: handler,
		})
	}

	// Network Management
	addTool("get_network_sites", "Get all sites from Unifi Network", s.getNetworkSites, map[string]any{})
	addTool("get_network_devices", "Get all devices from Unifi Network", s.getNetworkDevices, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_device_detailed", "Get detailed information about a specific device", s.getDeviceDetailed, map[string]any{
		"site_id":   map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"device_id": map[string]any{"type": "string", "description": "Device ID (required)"},
	})
	addTool("get_device_stats", "Get statistics for a specific device", s.getDeviceStats, map[string]any{
		"site_id":   map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"device_id": map[string]any{"type": "string", "description": "Device ID (required)"},
	})
	addTool("get_network_info", "Get UniFi Network application version and info", s.getNetworkInfo, map[string]any{})
	addTool("get_pending_devices", "Get devices pending adoption", s.getPendingDevices, map[string]any{})

	// WiFi Management
	addTool("get_wifi_networks", "Get WiFi networks from a site", s.getWiFiNetworks, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_wifi_network_detailed", "Get detailed information about a specific WiFi network", s.getWiFiNetworkDetailed, map[string]any{
		"site_id":    map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"network_id": map[string]any{"type": "string", "description": "Network ID (required)"},
	})
	addTool("get_wifi_broadcasts", "Get WiFi broadcast SSIDs from a site", s.getWiFiBroadcasts, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// Clients
	addTool("get_network_clients", "Get network clients from a site", s.getNetworkClients, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"limit":   map[string]any{"type": "integer", "description": "Limit (optional, default 25)"},
		"offset":  map[string]any{"type": "integer", "description": "Offset (optional, default 0)"},
	})
	addTool("get_client_detailed", "Get detailed information about a specific client", s.getClientDetailed, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"mac":     map[string]any{"type": "string", "description": "Client MAC address (required)"},
	})
	addTool("get_client_stats", "Get client statistics from a site", s.getClientStats, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// Health & Status Checks
	addTool("get_site_health", "Get health status of a site", s.getSiteHealth, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("check_network_endpoint_health", "Check health status of the Unifi Network endpoint", s.checkNetworkEndpointHealth, map[string]any{})
	addTool("check_protect_endpoint_health", "Check health status of the Unifi Protect endpoint", s.checkProtectEndpointHealth, map[string]any{})

	// Firewall & Security
	addTool("get_firewall_zones", "Get firewall zones from a site", s.getFirewallZones, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_firewall_zone_detailed", "Get detailed information about a specific firewall zone", s.getFirewallZoneDetailed, map[string]any{
		"site_id":          map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"firewall_zone_id": map[string]any{"type": "string", "description": "Firewall zone ID (required)"},
	})
	addTool("get_acl_rules", "Get ACL rules from a site", s.getACLRules, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_acl_rule_detailed", "Get detailed information about a specific ACL rule", s.getACLRuleDetailed, map[string]any{
		"site_id":     map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"acl_rule_id": map[string]any{"type": "string", "description": "ACL rule ID (required)"},
	})
	addTool("get_hotspot_vouchers", "Get hotspot vouchers from a site", s.getHotspotVouchers, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_hotspot_voucher_detailed", "Get detailed information about a specific hotspot voucher", s.getHotspotVoucherDetailed, map[string]any{
		"site_id":    map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"voucher_id": map[string]any{"type": "string", "description": "Voucher ID (required)"},
	})
	addTool("get_traffic_rules", "Get traffic rules from a site", s.getTrafficRules, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_traffic_rule_detailed", "Get detailed information about a specific traffic matching rule", s.getTrafficRuleDetailed, map[string]any{
		"site_id":                  map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"traffic_matching_list_id": map[string]any{"type": "string", "description": "Traffic matching list ID (required)"},
	})

	// VPN
	addTool("get_vpn_servers", "Get VPN server configurations from a site", s.getVPNServers, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// Network Configuration
	addTool("get_device_tags", "Get device tags from a site", s.getDeviceTags, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_wan_config", "Get WAN configuration from a site", s.getWANConfig, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_radius_profiles", "Get RADIUS server profiles from a site", s.getRADIUSProfiles, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// DPI
	addTool("get_dpi_categories", "Get DPI traffic categories", s.getDPICategories, map[string]any{})
	addTool("get_dpi_apps", "Get DPI applications", s.getDPIApps, map[string]any{})
	addTool("get_dpi_applications", "Get DPI applications list", s.getDPIApplications, map[string]any{})

	// Update handlers
	addTool("patch_wifi_network", "Update WiFi network settings", s.patchWiFiNetwork, map[string]any{
		"site_id":    map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"network_id": map[string]any{"type": "string", "description": "Network ID (required)"},
		"settings":   map[string]any{"type": "object", "description": "Settings to update (required)"},
	})
	addTool("patch_firewall_zone", "Update firewall zone", s.patchFirewallZone, map[string]any{
		"site_id":  map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"zone_id":  map[string]any{"type": "string", "description": "Zone ID (required)"},
		"settings": map[string]any{"type": "object", "description": "Settings to update (required)"},
	})
	addTool("patch_acl_rule", "Update ACL rule", s.patchACLRule, map[string]any{
		"site_id":  map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"rule_id":  map[string]any{"type": "string", "description": "Rule ID (required)"},
		"settings": map[string]any{"type": "object", "description": "Settings to update (required)"},
	})
	addTool("patch_hotspot_voucher", "Update hotspot voucher", s.patchHotspotVoucher, map[string]any{
		"site_id":    map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"voucher_id": map[string]any{"type": "string", "description": "Voucher ID (required)"},
		"settings":   map[string]any{"type": "object", "description": "Settings to update (required)"},
	})
	addTool("patch_traffic_rule", "Update traffic rule", s.patchTrafficRule, map[string]any{
		"site_id":  map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"rule_id":  map[string]any{"type": "string", "description": "Rule ID (required)"},
		"settings": map[string]any{"type": "object", "description": "Settings to update (required)"},
	})

	// Create handlers
	addTool("create_wifi_network", "Create a new WiFi network", s.createWiFiNetwork, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "WiFi network configuration (required)"},
	})
	addTool("create_firewall_zone", "Create a new firewall zone", s.createFirewallZone, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "Firewall zone configuration (required)"},
	})
	addTool("create_acl_rule", "Create a new ACL rule", s.createACLRule, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "ACL rule configuration (required)"},
	})
	addTool("create_hotspot_voucher", "Create a new hotspot voucher", s.createHotspotVoucher, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "Voucher configuration (required)"},
	})
	addTool("create_traffic_rule", "Create a new traffic rule", s.createTrafficRule, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "Traffic rule configuration (required)"},
	})
	addTool("create_vpn_tunnel", "Create a new VPN tunnel", s.createVPNTunnel, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
		"config":  map[string]any{"type": "object", "description": "VPN tunnel configuration (required)"},
	})

	s.server.AddTools(tools...)
}

// GET Handlers

func (s *Server) getNetworkSites(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_network_sites")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	sites, err := s.networkClient.GetSites(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get sites", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"sites": sites,
		"count": len(sites),
	})
}

func (s *Server) getNetworkDevices(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_network_devices")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	devices, err := s.networkClient.GetDevices(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get devices", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getDeviceDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_device_detailed")

	siteID := request.GetString("site_id", "")
	deviceID := request.GetString("device_id", "")

	if deviceID == "" {
		return mcp.NewToolResultError("device_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	device, err := s.networkClient.GetDeviceDetailed(ctx, resolvedSiteID, deviceID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get device details", err), nil
	}

	result := map[string]interface{}{
		"device":    device,
		"site_id":   resolvedSiteID,
		"device_id": deviceID,
	}

	return mcp.NewToolResultJSON(result)
}

func (s *Server) getDeviceStats(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_device_stats")

	siteID := request.GetString("site_id", "")
	deviceID := request.GetString("device_id", "")

	if deviceID == "" {
		return mcp.NewToolResultError("device_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	stats, err := s.networkClient.GetDeviceStats(ctx, resolvedSiteID, deviceID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get device stats", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"stats":     stats,
		"site_id":   resolvedSiteID,
		"device_id": deviceID,
	})
}

func (s *Server) getNetworkInfo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_network_info")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	info, err := s.networkClient.GetInfo(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get network info", err), nil
	}

	return mcp.NewToolResultJSON(info)
}

func (s *Server) getPendingDevices(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_pending_devices")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	devices, err := s.networkClient.GetPendingDevices(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get pending devices", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"devices": devices,
		"count":   len(devices),
	})
}

func (s *Server) getWiFiNetworks(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_wifi_networks")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	networks, err := s.networkClient.GetWiFiNetworks(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get wifi networks", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"networks": networks,
		"count":    len(networks),
		"site_id":  resolvedSiteID,
	})
}

func (s *Server) getWiFiBroadcasts(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_wifi_broadcasts")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	broadcasts, err := s.networkClient.GetWiFiBroadcasts(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get wifi broadcasts", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"broadcasts": broadcasts,
		"count":      len(broadcasts),
		"site_id":    resolvedSiteID,
	})
}

func (s *Server) getNetworkClients(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_network_clients")

	siteID := request.GetString("site_id", "")
	limit := request.GetInt("limit", 25)
	offset := request.GetInt("offset", 0)

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	clients, err := s.networkClient.GetClients(ctx, resolvedSiteID, limit, offset)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get network clients", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
		"site_id": resolvedSiteID,
		"limit":   limit,
		"offset":  offset,
	})
}

func (s *Server) getClientDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_client_detailed")

	siteID := request.GetString("site_id", "")
	mac := request.GetString("mac", "")

	if mac == "" {
		return mcp.NewToolResultError("mac is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	client, err := s.networkClient.GetClientDetailed(ctx, resolvedSiteID, mac)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get client details", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"client":  client,
		"site_id": resolvedSiteID,
		"mac":     mac,
	})
}

func (s *Server) getClientStats(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_client_stats")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	stats, err := s.networkClient.GetClientStats(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get client stats", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"stats":   stats,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getFirewallZones(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_firewall_zones")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	zones, err := s.networkClient.GetFirewallZones(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get firewall zones", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"zones":   zones,
		"count":   len(zones),
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getACLRules(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_acl_rules")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	rules, err := s.networkClient.GetACLRules(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get acl rules", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"rules":   rules,
		"count":   len(rules),
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getHotspotVouchers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_hotspot_vouchers")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	vouchers, err := s.networkClient.GetHotspotVouchers(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get hotspot vouchers", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"vouchers": vouchers,
		"count":    len(vouchers),
		"site_id":  resolvedSiteID,
	})
}

func (s *Server) getTrafficRules(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_traffic_rules")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	rules, err := s.networkClient.GetTrafficRules(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get traffic rules", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"rules":   rules,
		"count":   len(rules),
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getVPNServers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_vpn_servers")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	servers, err := s.networkClient.GetVPNServers(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get vpn servers", err), nil
	}

	result := map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
		"site_id": resolvedSiteID,
	}

	return mcp.NewToolResultJSON(result)
}

func (s *Server) getDPICategories(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_dpi_categories")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	categories, err := s.networkClient.GetDPICategories(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get dpi categories", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"categories": categories,
		"count":      len(categories),
	})
}

func (s *Server) getDPIApps(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_dpi_apps")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	apps, err := s.networkClient.GetDPIApplications(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get dpi apps", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"apps":  apps,
		"count": len(apps),
	})
}

// PATCH Handlers

func (s *Server) patchWiFiNetwork(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: patch_wifi_network")

	siteID := request.GetString("site_id", "")
	networkID := request.GetString("network_id", "")
	args := request.GetArguments()
	settings, ok := args["settings"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("settings must be an object"), nil
	}

	if networkID == "" {
		return mcp.NewToolResultError("network_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.PatchWiFiNetwork(ctx, resolvedSiteID, networkID, settings)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to update wifi network", err), nil
	}

	result["success"] = true
	result["network_id"] = networkID
	result["site_id"] = resolvedSiteID
	return mcp.NewToolResultJSON(result)
}

func (s *Server) patchFirewallZone(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: patch_firewall_zone")

	siteID := request.GetString("site_id", "")
	zoneID := request.GetString("zone_id", "")
	args := request.GetArguments()
	settings, ok := args["settings"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("settings must be an object"), nil
	}

	if zoneID == "" {
		return mcp.NewToolResultError("zone_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.PatchFirewallZone(ctx, resolvedSiteID, zoneID, settings)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to update firewall zone", err), nil
	}

	result["success"] = true
	result["zone_id"] = zoneID
	result["site_id"] = resolvedSiteID
	return mcp.NewToolResultJSON(result)
}

func (s *Server) patchACLRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: patch_acl_rule")

	siteID := request.GetString("site_id", "")
	ruleID := request.GetString("rule_id", "")
	args := request.GetArguments()
	settings, ok := args["settings"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("settings must be an object"), nil
	}

	if ruleID == "" {
		return mcp.NewToolResultError("rule_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.PatchACLRule(ctx, resolvedSiteID, ruleID, settings)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to update acl rule", err), nil
	}

	result["success"] = true
	result["rule_id"] = ruleID
	result["site_id"] = resolvedSiteID
	return mcp.NewToolResultJSON(result)
}

func (s *Server) patchHotspotVoucher(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: patch_hotspot_voucher")

	siteID := request.GetString("site_id", "")
	voucherID := request.GetString("voucher_id", "")
	args := request.GetArguments()
	settings, ok := args["settings"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("settings must be an object"), nil
	}

	if voucherID == "" {
		return mcp.NewToolResultError("voucher_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.PatchHotspotVoucher(ctx, resolvedSiteID, voucherID, settings)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to update hotspot voucher", err), nil
	}

	result["success"] = true
	result["voucher_id"] = voucherID
	result["site_id"] = resolvedSiteID
	return mcp.NewToolResultJSON(result)
}

func (s *Server) patchTrafficRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: patch_traffic_rule")

	siteID := request.GetString("site_id", "")
	ruleID := request.GetString("rule_id", "")
	args := request.GetArguments()
	settings, ok := args["settings"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("settings must be an object"), nil
	}

	if ruleID == "" {
		return mcp.NewToolResultError("rule_id is required"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.PatchTrafficRule(ctx, resolvedSiteID, ruleID, settings)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to update traffic rule", err), nil
	}

	result["success"] = true
	result["rule_id"] = ruleID
	result["site_id"] = resolvedSiteID
	return mcp.NewToolResultJSON(result)
}

// POST Handlers

func (s *Server) createWiFiNetwork(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_wifi_network")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateWiFiNetwork(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create wifi network", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"network": result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) createFirewallZone(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_firewall_zone")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateFirewallZone(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create firewall zone", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"zone":    result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) createACLRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_acl_rule")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateACLRule(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create acl rule", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"rule":    result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) createHotspotVoucher(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_hotspot_voucher")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateHotspotVoucher(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create hotspot voucher", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"voucher": result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) createTrafficRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_traffic_rule")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateTrafficRule(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create traffic rule", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"rule":    result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) createVPNTunnel(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: create_vpn_tunnel")

	siteID := request.GetString("site_id", "")
	args := request.GetArguments()
	config, ok := args["config"].(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("config must be an object"), nil
	}

	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	result, err := s.networkClient.CreateVPNTunnel(ctx, resolvedSiteID, config)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to create vpn tunnel", err), nil
	}

	return mcp.NewToolResultJSON(map[string]interface{}{
		"success": true,
		"tunnel":  result,
		"site_id": resolvedSiteID,
	})
}

func (s *Server) getWiFiNetworkDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_wifi_network_detailed")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	networkID := request.GetString("network_id", "")
	if networkID == "" {
		return mcp.NewToolResultErrorFromErr("Missing required parameter: network_id", nil), nil
	}
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	network, err := s.networkClient.GetWiFiNetworkDetailed(ctx, resolvedSiteID, networkID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get network details", err), nil
	}
	return mcp.NewToolResultJSON(network)
}

func (s *Server) getSiteHealth(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_site_health")

	siteID := request.GetString("site_id", "")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		s.logger.WithError(err).Error("Failed to authenticate with Network")
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	// Resolve site ID (if empty, uses first site)
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to resolve site ID")
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}

	health, err := s.networkClient.GetHealth(ctx, resolvedSiteID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get health")
		return mcp.NewToolResultErrorFromErr("Failed to get health", err), nil
	}

	result := map[string]interface{}{
		"health":  health,
		"site_id": resolvedSiteID,
	}

	return mcp.NewToolResultJSON(result)
}

func (s *Server) checkNetworkEndpointHealth(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: check_network_endpoint_health")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		s.logger.WithError(err).Error("Failed to authenticate with Network")
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	health, err := s.networkClient.CheckEndpointHealth(ctx)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check Network endpoint health")
		return mcp.NewToolResultErrorFromErr("Failed to check endpoint health", err), nil
	}

	result := map[string]interface{}{
		"endpoint": "Unifi Network",
		"health":   health,
	}

	return mcp.NewToolResultJSON(result)
}

func (s *Server) checkProtectEndpointHealth(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: check_protect_endpoint_health")

	if err := s.networkClient.Authenticate(ctx); err != nil {
		s.logger.WithError(err).Error("Failed to authenticate with Network")
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}

	result := map[string]interface{}{
		"endpoint": "Unifi Protect",
		"message":  "Protect endpoint health check is not available in network-mcp. Use unifi-mcp for combined access.",
		"status":   "skipped",
	}

	return mcp.NewToolResultJSON(result)
}

func (s *Server) getFirewallZoneDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_firewall_zone_detailed")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	zoneID := request.GetString("firewall_zone_id", "")
	if zoneID == "" {
		return mcp.NewToolResultErrorFromErr("Missing required parameter: firewall_zone_id", nil), nil
	}
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	zone, err := s.networkClient.GetFirewallZoneDetailed(ctx, resolvedSiteID, zoneID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get firewall zone details", err), nil
	}
	return mcp.NewToolResultJSON(zone)
}

func (s *Server) getACLRuleDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_acl_rule_detailed")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	ruleID := request.GetString("acl_rule_id", "")
	if ruleID == "" {
		return mcp.NewToolResultErrorFromErr("Missing required parameter: acl_rule_id", nil), nil
	}
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	rule, err := s.networkClient.GetACLRuleDetailed(ctx, resolvedSiteID, ruleID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get ACL rule details", err), nil
	}
	return mcp.NewToolResultJSON(rule)
}

func (s *Server) getHotspotVoucherDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_hotspot_voucher_detailed")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	voucherID := request.GetString("voucher_id", "")
	if voucherID == "" {
		return mcp.NewToolResultErrorFromErr("Missing required parameter: voucher_id", nil), nil
	}
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	voucher, err := s.networkClient.GetHotspotVoucherDetailed(ctx, resolvedSiteID, voucherID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get voucher details", err), nil
	}
	return mcp.NewToolResultJSON(voucher)
}

func (s *Server) getTrafficRuleDetailed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_traffic_rule_detailed")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	ruleID := request.GetString("traffic_matching_list_id", "")
	if ruleID == "" {
		return mcp.NewToolResultErrorFromErr("Missing required parameter: traffic_matching_list_id", nil), nil
	}
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	rule, err := s.networkClient.GetTrafficRuleDetailed(ctx, resolvedSiteID, ruleID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get traffic rule details", err), nil
	}
	return mcp.NewToolResultJSON(rule)
}

func (s *Server) getDeviceTags(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_device_tags")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	tags, err := s.networkClient.GetDeviceTags(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get device tags", err), nil
	}
	result := map[string]interface{}{
		"tags":    tags,
		"count":   len(tags),
		"site_id": resolvedSiteID,
	}
	return mcp.NewToolResultJSON(result)
}

func (s *Server) getWANConfig(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_wan_config")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	wanConfig, err := s.networkClient.GetWANConfig(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get WAN config", err), nil
	}
	result := map[string]interface{}{
		"wans":    wanConfig,
		"count":   len(wanConfig),
		"site_id": resolvedSiteID,
	}
	return mcp.NewToolResultJSON(result)
}

func (s *Server) getRADIUSProfiles(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_radius_profiles")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	siteID := request.GetString("site_id", "")
	resolvedSiteID, err := s.resolveSiteID(ctx, siteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to resolve site ID", err), nil
	}
	profiles, err := s.networkClient.GetRADIUSProfiles(ctx, resolvedSiteID)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get RADIUS profiles", err), nil
	}
	result := map[string]interface{}{
		"profiles": profiles,
		"count":    len(profiles),
		"site_id":  resolvedSiteID,
	}
	return mcp.NewToolResultJSON(result)
}

func (s *Server) getDPIApplications(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debug("Tool called: get_dpi_applications")
	if err := s.networkClient.Authenticate(ctx); err != nil {
		return mcp.NewToolResultErrorFromErr("Authentication failed", err), nil
	}
	applications, err := s.networkClient.GetDPIApplications(ctx)
	if err != nil {
		return mcp.NewToolResultErrorFromErr("Failed to get DPI applications", err), nil
	}
	result := map[string]interface{}{
		"applications": applications,
		"count":        len(applications),
	}
	return mcp.NewToolResultJSON(result)
}

// ServeStdio starts the MCP server with stdio transport
func (s *Server) ServeStdio(ctx context.Context) error {
	s.logger.Info("Starting UniFi Network MCP Server")
	return server.ServeStdio(s.server)
}

// ServeHTTP starts the MCP server with HTTP transport
func (s *Server) ServeHTTP(addr string, ctx context.Context) error {
	s.logger.Infof("Starting UniFi Network MCP Server on HTTP at %s", addr)

	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Parse the MCP request
		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Log the request
		s.logger.Debugf("HTTP MCP request received: %v", requestData)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]string{
			"status": "MCP HTTP transport is available",
			"info":   "This is an HTTP endpoint. Use stdio transport for full MCP protocol support.",
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	return http.ListenAndServe(addr, nil)
}
