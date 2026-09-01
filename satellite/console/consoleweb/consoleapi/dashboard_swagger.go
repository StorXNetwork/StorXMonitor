// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleapi

// DashboardIconSwagger is the card icon object for dashboard stats.
type DashboardIconSwagger struct {
	BackgroundColor string `json:"backgroundColor" example:"#E8F0FE"`
	URL             string `json:"url" example:"/static/icons/protected-users.svg"`
}

// DashboardButtonSwagger is the optional card action button.
type DashboardButtonSwagger struct {
	Link      string `json:"link" example:"/billing"`
	Click     string `json:"click" example:""`
	Color     string `json:"color" example:"#2563EB"`
	Text      string `json:"text" example:"Upgrade"`
	TextColor string `json:"textColor" example:"#FFFFFF"`
}

// DashboardStatusSwagger is the optional status badge object.
type DashboardStatusSwagger struct {
	Value           string `json:"value" example:"84% Used"`
	BackgroundColor string `json:"backgroundColor" example:"#18DB351A"`
	TextColor       string `json:"textColor" example:"#388E3C"`
}

// DashboardStatsCardSwaggerResponse represents one card in GET /api/v0/dashboard/stats response.
type DashboardStatsCardSwaggerResponse struct {
	Title       string                  `json:"title" example:"Protected Users"`
	Description string                  `json:"description" example:"Google accounts with backup enabled"`
	Icon        DashboardIconSwagger    `json:"icon"`
	Button      *DashboardButtonSwagger `json:"button,omitempty"`
	Status      *DashboardStatusSwagger `json:"status,omitempty"`
	Value1      interface{}             `json:"value_1,omitempty" swaggertype:"string" example:"124"`
	Value1Label string                  `json:"value_1_label,omitempty" example:""`
	Value2      interface{}             `json:"value_2,omitempty" swaggertype:"string" example:"+2 this week"`
	Value2Label string                  `json:"value_2_label,omitempty" example:"growth_this_week"`
}
