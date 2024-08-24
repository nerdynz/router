package router

import (
	"net/http"
	"os"
	"strings"

	"github.com/go-zoo/bone"
	"github.com/nerdynz/datastore"
	"github.com/nerdynz/flow"
	"github.com/nerdynz/security"
	"github.com/unrolled/render"
)

// CustomRouter wraps gorilla mux with database, redis and renderer
type CustomRouter struct {
	// Router *mux.Router
	Mux         *bone.Mux
	Renderer    *render.Render
	Key         security.Key
	Store       *datastore.Datastore
	AuthHandler func(w http.ResponseWriter, req *http.Request, flw *flow.Flow, store *datastore.Datastore, fn CustomHandlerFunc, authMethod string)
}

type CustomHandlerFunc func(w http.ResponseWriter, req *http.Request, flw *flow.Flow, store *datastore.Datastore)

func New(renderer *render.Render, s *datastore.Datastore, key security.Key, caseSensitive bool) *CustomRouter {
	customRouter := &CustomRouter{}
	r := bone.New()
	r.CaseSensitive = caseSensitive
	customRouter.Mux = r
	customRouter.Store = s
	customRouter.Key = key
	customRouter.Renderer = renderer
	customRouter.AuthHandler = authenticate
	return customRouter
}

func CustomAuth(renderer *render.Render, s *datastore.Datastore, key security.Key, authFn func(w http.ResponseWriter, req *http.Request, flw *flow.Flow, store *datastore.Datastore, fn CustomHandlerFunc, authMethod string)) *CustomRouter {
	customRouter := New(renderer, s, key, true)
	customRouter.AuthHandler = authFn
	return customRouter
}

// GET - Get handler
func (customRouter *CustomRouter) Application(route string, path string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, customRouter.appHandler(path))
}

func (customRouter *CustomRouter) GET(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, customRouter.handler("GET", routeFunc, securityType))
}

// POST - Post handler
func (customRouter *CustomRouter) POST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {

	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customRouter.handler("POST", routeFunc, securityType))
}

// PST - Post handler with pst for tidier lines
func (customRouter *CustomRouter) PST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customRouter.handler("POST", routeFunc, securityType))
}

// PUT - Put handler
func (customRouter *CustomRouter) PUT(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PutFunc(route, customRouter.handler("PUT", routeFunc, securityType))
}

// PATCH - Patch handler
func (customRouter *CustomRouter) PATCH(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PatchFunc(route, customRouter.handler("PATCH", routeFunc, securityType))
}

// OPTIONS - Options handler
func (customRouter *CustomRouter) OPTIONS(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.OptionsFunc(route, customRouter.handler("OPTIONS", routeFunc, securityType))
}

// DELETE - Delete handler
func (customRouter *CustomRouter) DELETE(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customRouter.handler("DELETE", routeFunc, securityType))
}

// DEL - Delete handler
func (customRouter *CustomRouter) DEL(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customRouter.handler("DELETE", routeFunc, securityType))
}

func (customRouter *CustomRouter) handler(reqType string, fn CustomHandlerFunc, authMethod string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		flow := flow.New(w, req, customRouter.Renderer, customRouter.Store, customRouter.Key)
		req.ParseForm()
		customRouter.AuthHandler(w, req, flow, customRouter.Store, fn, authMethod)
	}
}

// // DefaultHandler wraps default http functions in auth it does not pass the data store to them
// func DefaultHandler(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc {
// 	return authenticate(store, func(w http.ResponseWriter, req *http.Request) {
// 		fn(w, req)
// 	}, authMethod)
// }

func authenticate(w http.ResponseWriter, req *http.Request, flw *flow.Flow, store *datastore.Datastore, fn CustomHandlerFunc, authMethod string) {
	// canonical host
	canonical := store.Settings.Get("CANNONICAL_URL")
	if canonical != "" && store.Settings.IsProduction() { // set in ENV
		root := strings.ToLower(req.Host)
		if !strings.HasSuffix(root, "/") {
			root += "/"
		}
		if !strings.HasSuffix(canonical, "/") {
			canonical += "/"
		}
		// logrus.Info("root", root)
		// logrus.Info("root", canonical)
		if canonical != root {
			redirectURL := "http://"
			if store.Settings.GetBool("IS_HTTPS") {
				redirectURL = "https://"
			}
			redirectURL += strings.TrimRight(canonical, "/")
			if req.URL.Path != "" {
				redirectURL += req.URL.Path
				// logrus.Info("0", redirectURL)
			}
			if req.URL.RawQuery != "" {
				redirectURL += "?" + req.URL.RawQuery
				// logrus.Info("2", redirectURL)
			}
			if req.URL.Fragment != "" {
				redirectURL += "#" + req.URL.Fragment
				// logrus.Info("2", redirectURL)
			}

			http.Redirect(w, req, redirectURL, http.StatusMovedPermanently)
			return
		}
	}

	if authMethod == security.NoAuth {
		fn(w, req, flw, store)
		return
	}

	// if we are at this point then we want a login
	loggedInUser, _, err := flw.Padlock.LoggedInUser()
	if err != nil {
		if err.Error() == "redis: nil" {
			// ignore it, its expired from cache
			flw.ErrorJSON(http.StatusForbidden, "Login Expired", err)
		} else {
			flw.ErrorJSON(http.StatusForbidden, "Auth Failure", err)
		}
		return
	}

	if loggedInUser != nil {
		fn(w, req, flw, store)
		return
	}

	// if we have reached this point then the user doesn't have access
	if authMethod == security.Disallow {
		flw.ErrorJSON(http.StatusForbidden, "You're not currently logged in", err)
		return

	}
	if authMethod == security.Redirect {
		flw.Redirect("/Login", http.StatusSeeOther)
	}
}

func (customRouter *CustomRouter) appHandler(file string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		flw := flow.New(w, req, customRouter.Renderer, customRouter.Store, customRouter.Key)
		fullpath, err := os.Getwd()
		if err != nil {
			flw.ErrorJSON(http.StatusInternalServerError, "Failed to get current working directory", err)
		}
		fullpath += file
		flw.StaticFile(200, fullpath, "text/html; charset=utf-8")
	}
}
