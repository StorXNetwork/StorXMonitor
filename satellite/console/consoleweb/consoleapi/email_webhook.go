package consoleapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zeebo/errs"
	"storj.io/common/memory"
	"storj.io/storj/private/post"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/mailservice"
)

type EmailWebhook struct {
	service      *console.Service
	config       console.Config
	mailService  *mailservice.Service
	address      string
	supportEmail string
}

func NewEmailWebhook(service *console.Service, mailService *mailservice.Service, config console.Config, address, supportEmail string) *EmailWebhook {
	return &EmailWebhook{
		service:      service,
		mailService:  mailService,
		config:       config,
		address:      address,
		supportEmail: supportEmail,
	}
}

func (a *EmailWebhook) SendEmailByType(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Extract JWT token from request body
	var requestData struct {
		Token string `json:"token"`
	}

	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		a.serveJSONError(w, errs.New("error decoding request body"))
		return
	}

	if requestData.Token == "" {
		a.serveJSONError(w, errs.New("JWT token is required in request body"))
		return
	}

	tokenString := requestData.Token

	// Parse and validate JWT token using defaultEmailApiKey
	defaultEmailApiKey := a.config.EmailApiKey
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(defaultEmailApiKey), nil
	})
	if err != nil {
		fmt.Println("[DEBUG] Failed to parse JWT:", err)
		a.serveJSONError(w, errs.New("failed to parse JWT token: %s", err.Error()))
		return
	}

	if !token.Valid {
		fmt.Println("[DEBUG] JWT token is invalid")
		a.serveJSONError(w, errs.New("invalid JWT token"))
		return
	}

	// Extract claims from JWT
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		a.serveJSONError(w, errs.New("invalid JWT claims"))
		return
	}

	// Check expiration
	if exp, ok := claims["exp"]; ok {
		if expFloat, ok := exp.(float64); ok {
			if time.Now().Unix() > int64(expFloat) {
				a.serveJSONError(w, errs.New("JWT token expired"))
				return
			}
		}
	}

	// Extract email and emailType from claims
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		a.serveJSONError(w, errs.New("email claim is required in JWT"))
		return
	}

	emailType, ok := claims["emailType"].(string)
	if !ok || emailType == "" {
		a.serveJSONError(w, errs.New("emailType claim is required in JWT"))
		return
	}

	user, err := a.service.GetUsers().GetByEmail(ctx, email)
	if err != nil {
		fmt.Println("[DEBUG] Error finding user:", err)
		a.serveJSONError(w, err)
		return
	}

	// Get project owner
	projects, err := a.service.GetProjects().GetByUserID(ctx, user.ID)
	if err != nil {
		a.serveJSONError(w, err)
		return
	}

	for i, project := range projects {
		fmt.Println("[DEBUG] Processing project", i+1, "of", len(projects), "- Name:", project.Name, "ID:", project.ID)
		// Check if StorageLimit is nil to avoid panic
		if project.StorageLimit == nil {
			project.StorageLimit = new(memory.Size)
			*project.StorageLimit = memory.Size(0)
		}

		// Format storage size for email
		storageUsed := (float64(project.StorageUsed) * 100) / float64(*project.StorageLimit)

		if storageUsed == project.StorageUsedPercentage {
			continue
		}

		currentLevel := getStorageUsedLevel(storageUsed)
		levelInDatabase := getStorageUsedLevel(project.StorageUsedPercentage)

		if currentLevel <= levelInDatabase {
			err := a.service.GetProjects().UpdateStorageUsedPercentage(ctx, project.ID, storageUsed)
			if err != nil {
				a.serveJSONError(w, err)
			}
			continue
		}

		user, err := a.service.GetUsers().Get(ctx, project.OwnerID)
		if err != nil {
			a.serveJSONError(w, err)
			continue
		}

		// Send email based on type
		switch emailType {
		case "storage_usage":
			// For storage usage, we need project data - using defaults for now
			// In a real implementation, you'd want to get the user's projects and calculate actual usage
			a.mailService.SendRenderedAsync(ctx,
				[]post.Address{{Address: user.Email}},
				&console.StorageUsageEmail{
					UserName:    user.FullName,
					SignInLink:  a.address + "login",
					ContactLink: a.supportEmail,
					ProjectName: project.Name,                   // This should come from request or user's projects
					StorageUsed: float64(project.StorageUsed),   // This should be calculated from actual usage
					Percentage:  project.StorageUsedPercentage,  // This should be calculated from actual usage
					Limit:       float64(*project.StorageLimit), // Use user's project storage limit
				},
			)
		default:
			a.serveJSONError(w, errs.New("unsupported email type: %s", emailType))
			return
		}

		// Send success response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "email sent successfully"})
	}
}

// serveJSONError writes JSON error to response output stream.
func (a *EmailWebhook) serveJSONError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func getStorageUsedLevel(storageUsed float64) int {
	if storageUsed < 50 {
		return 0
	} else if storageUsed < 70 {
		return 1
	} else if storageUsed < 90 {
		return 2
	}
	return 3
}
