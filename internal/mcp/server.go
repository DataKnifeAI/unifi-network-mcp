package mcp

import (
	"context"
	"fmt"

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

	// Firewall & Security
	addTool("get_firewall_zones", "Get firewall zones from a site", s.getFirewallZones, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_acl_rules", "Get ACL rules from a site", s.getACLRules, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_hotspot_vouchers", "Get hotspot vouchers from a site", s.getHotspotVouchers, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})
	addTool("get_traffic_rules", "Get traffic rules from a site", s.getTrafficRules, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// VPN
	addTool("get_vpn_servers", "Get VPN server configurations from a site", s.getVPNServers, map[string]any{
		"site_id": map[string]any{"type": "string", "description": "Site ID (optional, defaults to first site)"},
	})

	// DPI
	addTool("get_dpi_categories", "Get DPI traffic categories", s.getDPICategories, map[string]any{})
	addTool("get_dpi_apps", "Get DPI applications", s.getDPIApps, map[string]any{})

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

// ServeStdio starts the MCP server with stdio transport
func (s *Server) ServeStdio(ctx context.Context) error {
	s.logger.Info("Starting UniFi Network MCP Server")
	return server.ServeStdio(s.server)
}
