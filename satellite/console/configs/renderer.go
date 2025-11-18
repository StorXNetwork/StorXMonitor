// Copyright (C) 2024 Storj Labs, Inc.
// See LICENSE for copying information.

package configs

import (
	"bytes"
	htmltemplate "html/template"
	texttemplate "text/template"

	"github.com/zeebo/errs"
)

var (
	// ErrRenderer represents errors from the template renderer.
	ErrRenderer = errs.Class("renderer")
)

// Renderer handles template rendering with variable substitution.
type Renderer struct{}

// NewRenderer creates a new template renderer.
func NewRenderer() *Renderer {
	return &Renderer{}
}

// RenderTextTemplate renders a text template with the given variables.
func (r *Renderer) RenderTextTemplate(templateStr string, variables map[string]interface{}) (string, error) {
	tmpl, err := texttemplate.New("text").Parse(templateStr)
	if err != nil {
		return "", ErrRenderer.Wrap(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, variables); err != nil {
		return "", ErrRenderer.Wrap(err)
	}

	return buf.String(), nil
}

// RenderHTMLTemplate renders an HTML template with the given variables.
func (r *Renderer) RenderHTMLTemplate(templateStr string, variables map[string]interface{}) (string, error) {
	tmpl, err := htmltemplate.New("html").Parse(templateStr)
	if err != nil {
		return "", ErrRenderer.Wrap(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, variables); err != nil {
		return "", ErrRenderer.Wrap(err)
	}

	return buf.String(), nil
}

// RenderTemplate renders a template based on the template type (email or push).
func (r *Renderer) RenderTemplate(templateData TemplateData, variables map[string]interface{}) (title string, body string, subject string, err error) {
	// Merge default variables with provided variables
	mergedVars := make(map[string]interface{})

	// First, add default variables
	if templateData.DefaultVariables != nil {
		for k, v := range templateData.DefaultVariables {
			mergedVars[k] = v
		}
	}

	// Then, override with provided variables (higher priority)
	for k, v := range variables {
		mergedVars[k] = v
	}

	// Render title template (for push notifications)
	if templateData.TitleTemplate != "" {
		title, err = r.RenderTextTemplate(templateData.TitleTemplate, mergedVars)
		if err != nil {
			return "", "", "", ErrRenderer.Wrap(err)
		}
	}

	// Render body template
	if templateData.BodyTemplate != "" {
		if templateData.Type == "email" {
			body, err = r.RenderHTMLTemplate(templateData.BodyTemplate, mergedVars)
		} else {
			// For push notifications, use text template and escape HTML
			body, err = r.RenderTextTemplate(templateData.BodyTemplate, mergedVars)
		}
		if err != nil {
			return "", "", "", ErrRenderer.Wrap(err)
		}
	}

	// Render subject (for email templates)
	if templateData.Subject != "" {
		subject, err = r.RenderTextTemplate(templateData.Subject, mergedVars)
		if err != nil {
			return "", "", "", ErrRenderer.Wrap(err)
		}
	}

	return title, body, subject, nil
}

// MergeUserPreferences merges user preferences with template defaults and runtime variables.
func MergeUserPreferences(templateDefaults map[string]interface{}, userCustomVars map[string]interface{}, runtimeVars map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})

	// 1. Template default variables (lowest priority)
	if templateDefaults != nil {
		for k, v := range templateDefaults {
			merged[k] = v
		}
	}

	// 2. User preference custom variables (medium priority)
	if userCustomVars != nil {
		for k, v := range userCustomVars {
			merged[k] = v
		}
	}

	// 3. Runtime-provided variables (highest priority)
	if runtimeVars != nil {
		for k, v := range runtimeVars {
			merged[k] = v
		}
	}

	return merged
}

// ValidateVariables validates that all required variables are present.
func ValidateVariables(templateData TemplateData, variables map[string]interface{}) error {
	if templateData.Variables == nil {
		return nil
	}

	var missing []string
	for varName, varDef := range templateData.Variables {
		// Check if variable is required
		if varDefMap, ok := varDef.(map[string]interface{}); ok {
			if required, ok := varDefMap["required"].(bool); ok && required {
				if _, exists := variables[varName]; !exists {
					missing = append(missing, varName)
				}
			}
		}
	}

	if len(missing) > 0 {
		return ErrRenderer.New("missing required variables: %v", missing)
	}

	return nil
}
