package gitlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// parse errors
var (
	ErrEventNotSpecifiedToParse      = errors.New("no Event specified to parse")
	ErrInvalidHTTPMethod             = errors.New("invalid HTTP Method")
	ErrMissingGitLabEventHeader      = errors.New("missing X-Gitlab-Event Header")
	ErrGitLabTokenVerificationFailed = errors.New("X-Gitlab-Token validation failed")
	ErrEventNotFound                 = errors.New("event not defined to be parsed")
	ErrParsingPayload                = errors.New("error parsing payload")
	ErrParsingSystemPayload          = errors.New("error parsing system payload")
	ErrUnknownSystemEvent            = errors.New("unknown system event")
	// ErrHMACVerificationFailed    = errors.New("HMAC verification failed")
)

// GitLab hook types
const (
	PushEvents               Event = "Push Hook"
	TagEvents                Event = "Tag Push Hook"
	IssuesEvents             Event = "Issue Hook"
	ConfidentialIssuesEvents Event = "Confidential Issue Hook"
	CommentEvents            Event = "Note Hook"
	MergeRequestEvents       Event = "Merge Request Hook"
	WikiPageEvents           Event = "Wiki Page Hook"
	PipelineEvents           Event = "Pipeline Hook"
	BuildEvents              Event = "Build Hook"
	JobEvents                Event = "Job Hook"
	SystemHookEvents         Event = "System Hook"

	objectPush         string = "push"
	objectTag          string = "tag_push"
	objectMergeRequest string = "merge_request"
	objectBuild        string = "build"

	SysEvtProjectCreate   string = "project_create"
	SysEvtProjectDestroy  string = "project_destroy"
	SysEvtProjectRename   string = "project_rename"
	SysEvtProjectTransfer string = "project_transfer"
	SysEvtProjectUpdate   string = "project_update"
	SysEvtAddToTeam       string = "user_add_to_team"
	SysEvtRemoveFromTeam  string = "user_remove_from_team"
	SysEvtTeamUpdate      string = "user_update_for_team"
	SysEvtUserCreate      string = "user_create"
	SysEvtUserDestroy     string = "user_destroy"
	SysEvtUserFailedLogin string = "user_failed_login"
	SysEvtUserRename      string = "user_rename"
	SysEvtKeyCreate       string = "key_create"
	SysEvtKeyDestroy      string = "key_destroy"
	SysEvtGroupCreate     string = "group_create"
	SysEvtGroupDestroy    string = "group_destroy"
	SysEvtGroupRename     string = "group_rename"
	SysEvtAddToGroup      string = "user_add_to_group"
	SysEvtRemoveFromGroup string = "user_remove_from_group"
	SysEvtGroupUpdate     string = "user_update_for_group"
)

// Option is a configuration option for the webhook
type Option func(*Webhook) error

// Options is a namespace var for configuration options
var Options = WebhookOptions{}

// WebhookOptions is a namespace for configuration option methods
type WebhookOptions struct{}

// Secret registers the GitLab secret
func (WebhookOptions) Secret(secret string) Option {
	return func(hook *Webhook) error {
		hook.secret = secret
		return nil
	}
}

// Webhook instance contains all methods needed to process events
type Webhook struct {
	secret string
}

// Event defines a GitLab hook event type by the X-Gitlab-Event Header
type Event string

// New creates and returns a WebHook instance denoted by the Provider type
func New(options ...Option) (*Webhook, error) {
	hook := new(Webhook)
	for _, opt := range options {
		if err := opt(hook); err != nil {
			return nil, errors.New("Error applying Option")
		}
	}
	return hook, nil
}

// Parse verifies and parses the events specified and returns the payload object or an error
func (hook Webhook) Parse(r *http.Request, events ...Event) (interface{}, error) {
	defer func() {
		_, _ = io.Copy(ioutil.Discard, r.Body)
		_ = r.Body.Close()
	}()

	if len(events) == 0 {
		return nil, ErrEventNotSpecifiedToParse
	}
	if r.Method != http.MethodPost {
		return nil, ErrInvalidHTTPMethod
	}

	// If we have a Secret set, we should check the MAC
	if len(hook.secret) > 0 {
		signature := r.Header.Get("X-Gitlab-Token")
		if signature != hook.secret {
			return nil, ErrGitLabTokenVerificationFailed
		}
	}

	event := r.Header.Get("X-Gitlab-Event")
	if len(event) == 0 {
		return nil, ErrMissingGitLabEventHeader
	}

	gitLabEvent := Event(event)

	payload, err := ioutil.ReadAll(r.Body)
	if err != nil || len(payload) == 0 {
		return nil, ErrParsingPayload
	}

	return eventParsing(gitLabEvent, events, payload)
}

func sysEvtParsing(eventName string, payload []byte) (interface{}, error) {
	switch eventName {
	case SysEvtProjectCreate:
		sysEvt := ProjectCreateSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtProjectDestroy:
		sysEvt := ProjectDestroySystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtProjectRename:
		sysEvt := ProjectRenameSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtProjectTransfer:
		sysEvt := ProjectTransferSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtProjectUpdate:
		sysEvt := ProjectUpdateSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtAddToTeam:
		sysEvt := NewTeamMemberSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtRemoveFromTeam:
		sysEvt := TeamMemberRemovedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtTeamUpdate:
		sysEvt := TeamMemberUpdatedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtUserCreate:
		sysEvt := UserCreatedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtUserDestroy:
		sysEvt := UserRemovedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtUserFailedLogin:
		sysEvt := UserFailedLoginSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtUserRename:
		sysEvt := UserRenamedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtKeyCreate:
		sysEvt := KeyAddedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtKeyDestroy:
		sysEvt := KeyRemovedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtGroupCreate:
		sysEvt := GroupCreatedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtGroupDestroy:
		sysEvt := GroupRemovedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtGroupRename:
		sysEvt := GroupRenamedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtAddToGroup:
		sysEvt := NewGroupMemberSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtRemoveFromGroup:
		sysEvt := GroupMemberRemovedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	case SysEvtGroupUpdate:
		sysEvt := GroupMemberUpdatedSystemEventPayload{}
		if err := json.Unmarshal(payload, &sysEvt); err != nil {
			return nil, ErrParsingSystemPayload
		}
		return sysEvt, nil
	default:
		return nil, fmt.Errorf("unknown system hook event %s", eventName)
	}

	return nil, ErrUnknownSystemEvent
}

func eventParsing(gitLabEvent Event, events []Event, payload []byte) (interface{}, error) {

	var found bool
	for _, evt := range events {
		if evt == gitLabEvent {
			found = true
			break
		}
	}
	// event not defined to be parsed
	if !found {
		return nil, ErrEventNotFound
	}

	switch gitLabEvent {
	case PushEvents:
		var pl PushEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case TagEvents:
		var pl TagEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case ConfidentialIssuesEvents:
		var pl ConfidentialIssueEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case IssuesEvents:
		var pl IssueEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case CommentEvents:
		var pl CommentEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case MergeRequestEvents:
		var pl MergeRequestEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case WikiPageEvents:
		var pl WikiPageEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case PipelineEvents:
		var pl PipelineEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err

	case BuildEvents:
		var pl BuildEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		return pl, err
	case JobEvents:
		var pl JobEventPayload
		err := json.Unmarshal([]byte(payload), &pl)
		if err != nil {
			return nil, err
		}
		if pl.ObjectKind == objectBuild {
			return eventParsing(BuildEvents, events, payload)
		}
		return pl, nil

	case SystemHookEvents:
		var pl SystemHookPayload
		err := json.Unmarshal([]byte(payload), &pl)
		if err != nil {
			return nil, err
		}
		switch pl.ObjectKind {
		case objectPush:
			return eventParsing(PushEvents, events, payload)
		case objectTag:
			return eventParsing(TagEvents, events, payload)
		case objectMergeRequest:
			return eventParsing(MergeRequestEvents, events, payload)
		default:
			switch pl.EventName {
			case objectPush:
				return eventParsing(PushEvents, events, payload)
			case objectTag:
				return eventParsing(TagEvents, events, payload)
			case objectMergeRequest:
				return eventParsing(MergeRequestEvents, events, payload)
			default:
				return sysEvtParsing(pl.EventName, payload)
			}
		}
	default:
		return nil, fmt.Errorf("unknown event %s", gitLabEvent)
	}
}
