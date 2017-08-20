package router

import (
	"context"
	"net/http"
	"os"
	"strings"

	"io/ioutil"

	"github.com/go-zoo/bone"
	"github.com/nerdynz/datastore"
	flow "github.com/nerdynz/flow"
	"github.com/nerdynz/security"
	"github.com/nerdynz/view"
)

// CustomRouter wraps gorilla mux with database, redis and renderer
type CustomRouter struct {
	// Router *mux.Router
	Mux   *bone.Mux
	Store *datastore.Datastore
}

func New(store *datastore.Datastore) *CustomRouter {
	customRouter := &CustomRouter{}
	r := bone.New()
	r.CaseSensitive = false
	r.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public/"))))
	// r.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets/"))))
	r.Handle("/attachments/", http.StripPrefix("/attachments/", http.FileServer(http.Dir(store.Settings.AttachmentsFolder))))
	customRouter.Mux = r
	customRouter.Store = store
	return customRouter
}

// GET - Get handler
func (customRouter *CustomRouter) Application(route string, path string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, appHandler(path))
}

func (customRouter *CustomRouter) GET(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, customHandler("GET", customRouter.Store, routeFunc, securityType))
}

// POST - Post handler
func (customRouter *CustomRouter) POST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customHandler("POST", customRouter.Store, routeFunc, securityType))
}

// PST - Post handler with pst for tidier lines
func (customRouter *CustomRouter) PST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customHandler("POST", customRouter.Store, routeFunc, securityType))
}

// PUT - Put handler
func (customRouter *CustomRouter) PUT(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PutFunc(route, customHandler("PUT", customRouter.Store, routeFunc, securityType))
}

// PATCH - Patch handler
func (customRouter *CustomRouter) PATCH(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PatchFunc(route, customHandler("PATCH", customRouter.Store, routeFunc, securityType))
}

// OPTIONS - Options handler
func (customRouter *CustomRouter) OPTIONS(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.OptionsFunc(route, customHandler("OPTIONS", customRouter.Store, routeFunc, securityType))
}

// DELETE - Delete handler
func (customRouter *CustomRouter) DELETE(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customHandler("DELETE", customRouter.Store, routeFunc, securityType))
}

// DEL - Delete handler
func (customRouter *CustomRouter) DEL(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customHandler("DELETE", customRouter.Store, routeFunc, securityType))
}

func customHandler(reqType string, store *datastore.Datastore, fn CustomHandlerFunc, authMethod string) http.HandlerFunc {
	return authenticate(store, func(w http.ResponseWriter, req *http.Request) {
		fn(flow.New(w, req, store))
	}, authMethod)
}

// DefaultHandler wraps default http functions in auth it does not pass the data store to them
func DefaultHandler(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc {
	return authenticate(store, func(w http.ResponseWriter, req *http.Request) {
		fn(w, req)
	}, authMethod)
}

func authenticate(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// canonical host
		if store.Settings.CanonicalURL != "" && store.Settings.ServerIsLVE { // set in ENV
			root := strings.ToLower(req.URL.Host + req.URL.Path)
			if !strings.HasSuffix(root, "/") {
				root += "/"
			}
			if store.Settings.CanonicalURL != root {
				redirectURL := store.Settings.CanonicalURL
				if req.URL.RawQuery != "" {
					redirectURL += "?" + req.URL.RawQuery
				}
				if req.URL.Fragment != "" {
					redirectURL += "#" + req.URL.Fragment
				}

				http.Redirect(w, req, redirectURL, http.StatusMovedPermanently)
				return
			}
		}

		// CSRF
		if store.Settings.CheckCSRFViaReferrer {

		}

		padlock := security.New(req, store)

		// check for a logged in user. We always check this incase we need it
		loggedInUser, err := padlock.LoggedInUser()

		// if we are at this point then we want a login
		if loggedInUser != nil {
			ctx := context.WithValue(req.Context(), "loggedInUser", loggedInUser)
			fn(w, req.WithContext(ctx))
			return
		} else if authMethod == security.NoAuth {
			fn(w, req)
			return
		} else if err != nil {
			// WE ONLY check the error after the above because if we aren't authenticating then we will get an error
			view.JSON(w, http.StatusInternalServerError, err.Error())
			return
		}

		// if we have reached this point then the user doesn't have access
		if authMethod == security.Disallow {
			view.JSON(w, http.StatusForbidden, "Not Logged In")
			return
		} else if authMethod == security.Redirect {
			http.Redirect(w, req, "/Login", http.StatusFound)
		}
	}
}

type CustomHandlerFunc func(context *flow.Context)

func appHandler(file string) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		fullpath, err := os.Getwd()
		if err != nil {
			view.JSON(w, http.StatusInternalServerError, err.Error())
		}
		fullpath += file
		// logrus.Info(fullpath)
		data, err := ioutil.ReadFile(fullpath)
		if err != nil {
			view.JSON(w, http.StatusInternalServerError, err.Error())
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	}
}
