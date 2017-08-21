package authz

import (
	"encoding/json"
	"fmt"
	"github.com/Sirupsen/logrus"
	logrus_syslog "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/docker/docker/pkg/authorization"
	"github.com/howeyc/fsnotify"
	"github.com/sdeepugd/authz/core"
	"io/ioutil"
	"log/syslog"
	"os"
	"path"
	"regexp"
	"strings"
	"github.com/docker/docker/runconfig"
	"bytes"
	"container/list"
	"path/filepath"
)

// BasicPolicy represent a single policy object that is evaluated in the authorization flow.
// Each policy object consists of multiple users and docker actions, where each user belongs to a single policy.
//
// The policies are evaluated according to the following flow:
//   For each policy object check
//      If the user belongs to the policy
//         If action in request in policy allow otherwise deny
//   If no appropriate policy found, return deny
//
// Remark: In basic flow, each user must have a unique policy.
// If a user is used by more than one policy, the results may be inconsistent
type BasicPolicy struct {
	Actions []string `json:"actions"` // Actions are the docker actions (mapped to authz terminology) that are allowed according to this policy
	// Action are are specified as regular expressions
	Users    []string `json:"users"`    // Users are the users for which this policy apply to
	Name     string   `json:"name"`     // Name is the policy name
	Readonly bool     `json:"readonly"` // Readonly indicates this policy only allow get commands
	Filepaths string `json:"path"`  //filepaths that the user allowed to mount.It is a localtion of allowed filepaths
	Mounts AllowedFilePaths
}

type AllowedFilePaths struct {
	AllowedPaths []string `json:"allowedmounts"`
}

const (
	// AuditHookSyslog indicates logs are streamed  to local syslog
	AuditHookSyslog = "syslog"

	// AuditHookFile indicates logs are streamed  to local syslog
	AuditHookFile = "file"

	// AuditHookStdout indicates logs are streamed to stdout
	AuditHookStdout = ""
)

// defaultAuditLogPath is the file test hook log path
const defaultAuditLogPath = "/var/log/authz-broker.log"

type basicAuthorizer struct {
	settings *BasicAuthorizerSettings
	policies []BasicPolicy
}

// BasicAuthorizerSettings provides settings for the basic authoerizer flow
type BasicAuthorizerSettings struct {
	PolicyPath string // PolicyPath is the path to the policy settings
}

// NewBasicAuthZAuthorizer creates a new basic authorizer
func NewBasicAuthZAuthorizer(settings *BasicAuthorizerSettings) core.Authorizer {
	return &basicAuthorizer{settings: settings}
}

// Init loads the basic authz plugin configuration from disk
func (f *basicAuthorizer) Init() error {

	err := f.loadPolicies()
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case ev := <-watcher.Event:
				if ev.IsModify() {
					err := f.loadPolicies()
					if err != nil {
						logrus.Errorf("Error refreshing policy %q", err.Error())
					}
				}
			case err := <-watcher.Error:
				logrus.Errorf("Settings watcher error '%v'", err)
			}
		}
	}()

	err = watcher.Watch(f.settings.PolicyPath)
	if err != nil {
		// Silently ignore watching error
		logrus.Errorf("Failed to start watching folder %q", err.Error())
	}

	return nil
}

func (f *basicAuthorizer) loadPolicies() error {
	data, err := ioutil.ReadFile(path.Join(f.settings.PolicyPath))

	if err != nil {
		return err
	}

	var policies []BasicPolicy
	for _, l := range strings.Split(string(data), "\n") {

		if l == "" {
			continue
		}

		var policy BasicPolicy
		err := json.Unmarshal([]byte(l), &policy)

		if policy.Filepaths != "" {
			policy.Mounts = loadAllowedMounts(policy.Filepaths)
		}

		if err != nil {
			logrus.Errorf("Failed to unmarshel policy entry %q %q", l, err.Error())
		}
		policies = append(policies, policy)
	}
	logrus.Infof("Loaded '%d' policies", len(policies))

	// Notify when user appears in duplicate policies
	userToPolicy := make(map[string]string)
	for _, policy := range policies {
		for _, u := range policy.Users {
			if userPolicy, ok := userToPolicy[u]; ok {
				logrus.Warnf("User %q already appears in policy %q. Only single policy applies. Undefined policy behavior %q",
					u,
					userPolicy,
					policy.Name)
			}
			userToPolicy[u] = policy.Name
		}

	}

	f.policies = policies
	return nil
}

func loadAllowedMounts(filepath string) AllowedFilePaths {
	data, err := ioutil.ReadFile(path.Join(filepath))
	if(err == nil){
		logrus.Error(err)
	}
	var filepaths AllowedFilePaths
	errjson := json.Unmarshal(data,&filepaths)
	if(errjson == nil){
		logrus.Error(errjson)
	}
	fmt.Println("data : ",filepath)
	return filepaths
}

func (f *basicAuthorizer) AuthZReq(authZReq *authorization.Request) *authorization.Response {

	logrus.Debugf("Received AuthZ request, method: '%s', url: '%s'", authZReq.RequestMethod, authZReq.RequestURI)

	action := core.ParseRoute(authZReq.RequestMethod, authZReq.RequestURI)

	for _, policy := range f.policies {
		for _, user := range policy.Users {
			if user == authZReq.User {
				for _, policyActionPattern := range policy.Actions {
					match, err := regexp.MatchString(policyActionPattern, action)
					if err != nil {
						logrus.Errorf("Failed to evaulate action %q against policy %q error %q", action, policyActionPattern, err.Error())
					}


					if match {

						if len(policy.Mounts.AllowedPaths) > 0{
							hostMount := getHostMountFromRequest(authZReq)
							isValidMount := AuthoriseMountsPaths(hostMount,policy.Mounts.AllowedPaths)
							if(!isValidMount){
								match = false
								return &authorization.Response{
									Allow: false,
									Msg:   fmt.Sprintf("action '%s' not allowed for user '%s' since the given mount path is not valid by policy '%s'", action, authZReq.User, policy.Name),
								}
							}
						}

						if policy.Readonly && authZReq.RequestMethod != "GET" {
							return &authorization.Response{
								Allow: false,
								Msg:   fmt.Sprintf("action '%s' not allowed for user '%s' by readonly policy '%s'", action, authZReq.User, policy.Name),
							}
						}

						return &authorization.Response{
							Allow: true,
							Msg:   fmt.Sprintf("action '%s' allowed for user '%s' by policy '%s'", action, authZReq.User, policy.Name),
						}
					}
				}
				return &authorization.Response{
					Allow: false,
					Msg:   fmt.Sprintf("action '%s' denied for user '%s' by policy '%s'", action, authZReq.User, policy.Name),
				}
			}
		}
	}

	return &authorization.Response{
		Allow: false,
		Msg:   fmt.Sprintf("no policy applied (user: '%s' action: '%s')", authZReq.User, action),
	}
}
func AuthoriseMountsPaths(hostMounts []string, allowedMounts []string) bool {
	for _,hostMount := range hostMounts {
		if(!isHostmountPresentinAllowedMount(hostMount,allowedMounts)){
			return false
		}
	}
	return true
}
func isHostmountPresentinAllowedMount(hostMount string, allowedMounts []string) bool {
	for _,allowedMount := range allowedMounts {
		if(isValidPaths(hostMount,allowedMount)){
			return true
		}
	}
	return false
}

func isValidPaths(host string, allowedMount string) bool {
	hosterr,hostExist,cleanhost := checkCleanandExists(host)
	if(hostExist && hosterr != nil){
		return strings.HasPrefix(cleanhost,allowedMount)
	}
	return false;
}

func isdir(path string) bool {
	fi, err := os.Lstat(path)
	if(err != nil){
		panic(err)
	}
	return (fi.Mode() & os.ModeDir != 0)
}

func checkCleanandExists(path string) (error,bool,string) {
	if _, err := os.Stat(path); err != nil {
		if (os.IsNotExist(err) && !isdir(path)) {
			return err,false,""
		}
	}
	return nil,true,filepath.Clean(path)
}

func getHostMountFromRequest(authreq *authorization.Request) []string {
	decoder := runconfig.ContainerDecoder{}
	_, hostConfig, _, _ := decoder.DecodeConfig(bytes.NewReader(authreq.RequestBody))
	hostmountlist := list.New()
	for _,bind := range hostConfig.Binds{
		mounts := strings.Split(bind,":")
		host := mounts[0]
		hostmountlist.PushBack(host)
	}
	hostmountarr := make([]string, hostmountlist.Len())
	for i := 0; i < hostmountlist.Len(); i++ {
		hostmountarr[i] = hostmountlist.Back().Value.(string)        // <-- changed
	}
	return hostmountarr
}

// AuthZRes always allow responses from server
func (f *basicAuthorizer) AuthZRes(authZReq *authorization.Request) *authorization.Response {
	return &authorization.Response{Allow: true}
}

// basicAuditor audit requset/response directly to standard output
type basicAuditor struct {
	logger   *logrus.Logger
	settings *BasicAuditorSettings
}

// NewBasicAuditor returns a new authz auditor that uses the specified logging hook (e.g., syslog or stdout)
func NewBasicAuditor(settings *BasicAuditorSettings) core.Auditor {
	b := &basicAuditor{settings: settings}
	return b
}

// BasicAuditorSettings are settings used by the basic auditor
type BasicAuditorSettings struct {
	LogHook string // LogHook is the log hook used to audit authorization data
	LogPath string // LogPath is the path to audit log file (if file hook is specified)
}

func (b *basicAuditor) AuditRequest(req *authorization.Request, pluginRes *authorization.Response) error {

	if req == nil {
		return fmt.Errorf("Authorization request is nil")
	}

	if pluginRes == nil {
		return fmt.Errorf("Authorization response is nil")
	}

	err := b.init()
	if err != nil {
		return err
	}
	// Default - file
	fields := logrus.Fields{
		"method": req.RequestMethod,
		"uri":    req.RequestURI,
		"user":   req.User,
		"allow":  pluginRes.Allow,
		"msg":    pluginRes.Msg,
	}

	if pluginRes != nil || pluginRes.Err != "" {
		fields["err"] = pluginRes.Err
	}

	b.logger.WithFields(fields).Info("Request")
	return nil
}

func (b *basicAuditor) AuditResponse(req *authorization.Request, pluginRes *authorization.Response) error {
	// Only log requests
	return nil
}

// init inits the auditor logger
func (b *basicAuditor) init() error {

	if b.settings == nil {
		return fmt.Errorf("Settings is not defeined")
	}

	if b.logger != nil {
		return nil
	}

	b.logger = logrus.New()
	b.logger.Formatter = &logrus.JSONFormatter{}

	switch b.settings.LogHook {
	case AuditHookSyslog:
		{
			hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_ERR, "authz")
			if err != nil {
				return err
			}
			b.logger.Hooks.Add(hook)
		}
	case AuditHookFile:
		{
			logPath := b.settings.LogPath
			if logPath == "" {
				logrus.Infof("Using default log file path '%s'", logPath)
				logPath = defaultAuditLogPath
			}

			os.MkdirAll(path.Dir(logPath), 0700)
			f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0750)
			if err != nil {
				return err
			}
			b.logger.Out = f
		}
	case AuditHookStdout:
		{
			// Default - stdout
		}
	default:
		return fmt.Errorf("Wrong log hook value '%s'", b.settings.LogHook)
	}

	return nil
}
