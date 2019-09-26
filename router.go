package router

import (
	"net/http"
	"os"
	"strings"

	"io/ioutil"

	"github.com/go-zoo/bone"
	"github.com/nerdynz/datastore"
	flow "github.com/nerdynz/flow"
	"github.com/nerdynz/security"
	"github.com/nerdynz/view"
	"github.com/sirupsen/logrus"
)

// CustomRouter wraps gorilla mux with database, redis and renderer
type CustomRouter struct {
	// Router *mux.Router
	Mux         *bone.Mux
	Store       *datastore.Datastore
	AuthHandler func(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc
}

func New(store *datastore.Datastore) *CustomRouter {
	customRouter := &CustomRouter{}
	r := bone.New()
	r.CaseSensitive = false
	// r.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public/"))))
	// r.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets/"))))
	// r.Handle("/attachments/", http.StripPrefix("/attachments/", http.FileServer(http.Dir(store.Settings.AttachmentsFolder))))
	customRouter.Mux = r
	customRouter.Store = store
	customRouter.AuthHandler = authenticate
	return customRouter
}

func CustomAuth(store *datastore.Datastore, authFn func(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc) *CustomRouter {
	customRouter := &CustomRouter{}
	r := bone.New()
	r.CaseSensitive = false
	// r.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public/"))))
	// r.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets/"))))
	// r.Handle("/attachments/", http.StripPrefix("/attachments/", http.FileServer(http.Dir(store.Settings.AttachmentsFolder))))
	customRouter.Mux = r
	customRouter.Store = store
	customRouter.AuthHandler = authFn
	return customRouter
}

// GET - Get handler
func (customRouter *CustomRouter) Application(route string, path string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, appHandler(path))
}

func (customRouter *CustomRouter) GET(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.GetFunc(route, customRouter.customHandler("GET", customRouter.Store, routeFunc, securityType))
}

// POST - Post handler
func (customRouter *CustomRouter) POST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customRouter.customHandler("POST", customRouter.Store, routeFunc, securityType))
}

// PST - Post handler with pst for tidier lines
func (customRouter *CustomRouter) PST(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PostFunc(route, customRouter.customHandler("POST", customRouter.Store, routeFunc, securityType))
}

// PUT - Put handler
func (customRouter *CustomRouter) PUT(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PutFunc(route, customRouter.customHandler("PUT", customRouter.Store, routeFunc, securityType))
}

// PATCH - Patch handler
func (customRouter *CustomRouter) PATCH(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.PatchFunc(route, customRouter.customHandler("PATCH", customRouter.Store, routeFunc, securityType))
}

// OPTIONS - Options handler
func (customRouter *CustomRouter) OPTIONS(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.OptionsFunc(route, customRouter.customHandler("OPTIONS", customRouter.Store, routeFunc, securityType))
}

// DELETE - Delete handler
func (customRouter *CustomRouter) DELETE(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customRouter.customHandler("DELETE", customRouter.Store, routeFunc, securityType))
}

// DEL - Delete handler
func (customRouter *CustomRouter) DEL(route string, routeFunc CustomHandlerFunc, securityType string) *bone.Route {
	//route = strings.ToLower(route)
	return customRouter.Mux.DeleteFunc(route, customRouter.customHandler("DELETE", customRouter.Store, routeFunc, securityType))
}

func (customRouter *CustomRouter) customHandler(reqType string, store *datastore.Datastore, fn CustomHandlerFunc, authMethod string) http.HandlerFunc {
	return customRouter.AuthHandler(store, func(w http.ResponseWriter, req *http.Request) {
		fn(flow.New(w, req, store))
	}, authMethod)
}

// // DefaultHandler wraps default http functions in auth it does not pass the data store to them
// func DefaultHandler(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc {
// 	return authenticate(store, func(w http.ResponseWriter, req *http.Request) {
// 		fn(w, req)
// 	}, authMethod)
// }

func authenticate(store *datastore.Datastore, fn http.HandlerFunc, authMethod string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// canonical host
		if store.Settings.CanonicalURL != "" && store.Settings.ServerIsLVE { // set in ENV
			canonical := store.Settings.CanonicalURL
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
				if store.Settings.IsSecured {
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

		// CSRF
		// if store.Settings.CheckCSRFViaReferrer {

		// }
		if authMethod == security.NoAuth {
			fn(w, req)
			return
		}

		tableName := "person" // default
		api := bone.GetValue(req, "api")
		if api == "api" || api == "admin" {
			// default - backwards compatibility
			tableName = "person" // we already did this above, this is just for clarity. the default should ALWAYS BE person
		} else if api != "" {
			tableName = api
		}

		// if we are at this point then we want a login
		// check for a logged in user. We always check this incase we need it
		loggedInUser, err := security.New(req, store).LoggedInUser()
		if err != nil {
			if err.Error() == "redis: nil" {
				// ignore it, its expired from cache
			} else {
				logrus.Error("Something wrong with Auth", err)
			}
		}
		if loggedInUser != nil && loggedInUser.TableName == tableName { // we are in the correct section of the website
			fn(w, req)
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
