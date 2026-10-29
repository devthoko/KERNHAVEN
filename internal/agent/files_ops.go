package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agent/files"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// streamHandler serves a stream operation: params are verified by the
// grant, body is the request body, and the handler writes the response.
type streamHandler func(ctx context.Context, params json.RawMessage, body io.Reader, w http.ResponseWriter) error

// longOps may run for hours (copies, emptying the trash).
var longOps = map[string]bool{agentproto.OpFilesCopy: true, agentproto.OpFilesTrashPurge: true}

// fileOperations are the M10 JSON operations of the storage role.
func fileOperations(f *files.Service) map[string]handler {
	return map[string]handler{
		agentproto.OpFilesRoots: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return f.Roots(), nil
		}),
		agentproto.OpFilesList: typed(func(ctx context.Context, p agentproto.FilesPath) (any, error) {
			return f.List(p)
		}),
		agentproto.OpFilesMkdir: typed(func(ctx context.Context, p agentproto.FilesPath) (any, error) {
			return agentproto.ActionResult{ID: p.Path, Changed: true}, f.Mkdir(p)
		}),
		agentproto.OpFilesRename: typed(func(ctx context.Context, p agentproto.FilesRename) (any, error) {
			return agentproto.ActionResult{ID: p.To, Changed: true}, f.Rename(p)
		}),
		agentproto.OpFilesCopy: typed(func(ctx context.Context, p agentproto.FilesCopy) (any, error) {
			return f.Copy(ctx, p)
		}),
		agentproto.OpFilesTrash: typed(func(ctx context.Context, p agentproto.FilesPath) (any, error) {
			return f.Trash(p, actorFrom(ctx))
		}),
		agentproto.OpFilesTrashList: typed(func(ctx context.Context, p agentproto.FilesPath) (any, error) {
			return f.TrashList(p)
		}),
		agentproto.OpFilesTrashRestore: typed(func(ctx context.Context, p agentproto.FilesTrashID) (any, error) {
			path, err := f.Restore(p)
			return agentproto.ActionResult{ID: path, Changed: true}, err
		}),
		agentproto.OpFilesTrashPurge: typed(func(ctx context.Context, p agentproto.FilesTrashID) (any, error) {
			return agentproto.ActionResult{ID: p.ID, Changed: true}, f.Purge(p)
		}),
		agentproto.OpFilesUploadFinish: typed(func(ctx context.Context, p agentproto.UploadFinish) (any, error) {
			return agentproto.ActionResult{ID: p.Path, Changed: true}, f.Finish(p)
		}),
		agentproto.OpFilesUploadAbort: typed(func(ctx context.Context, p agentproto.UploadFinish) (any, error) {
			return agentproto.ActionResult{ID: p.ID, Changed: true}, f.Abort(p)
		}),
	}
}

// streamOperations are offered by the files role (file contents) and the
// Docker agent (volume contents, M16).
func streamOperations(d Docker, o Options) map[string]streamHandler {
	f := o.Files
	if o.Storage != nil || o.Proxy != nil || o.Monitor != nil {
		return map[string]streamHandler{}
	}
	if f == nil {
		return volumeStreamOperations(d, o)
	}
	return map[string]streamHandler{
		agentproto.OpFilesRead: func(ctx context.Context, raw json.RawMessage, _ io.Reader, w http.ResponseWriter) error {
			p, err := decode[agentproto.FilesRead](raw)
			if err != nil {
				return err
			}
			meta, rc, err := f.Open(p)
			if err != nil {
				return err
			}
			defer rc.Close()
			mb, _ := json.Marshal(meta)
			w.Header().Set(agentproto.HeaderMeta, base64.StdEncoding.EncodeToString(mb))
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, rc) // a broken copy shows as a short body to the Core
			return nil
		},
		agentproto.OpFilesUploadAppend: func(ctx context.Context, raw json.RawMessage, body io.Reader, w http.ResponseWriter) error {
			p, err := decode[agentproto.UploadAppend](raw)
			if err != nil {
				return err
			}
			st, err := f.Append(p, body)
			if err != nil {
				return err
			}
			writeJSON(w, http.StatusOK, map[string]any{"result": st})
			return nil
		},
	}
}

// StreamOperationNames lists the stream operations of the files role.
func StreamOperationNames() []string {
	ops := streamOperations(nil, Options{Files: &files.Service{}})
	m := map[string]handler{}
	for n := range ops {
		m[n] = nil
	}
	return sortedNames(m)
}

// DockerStreamOperationNames lists the Docker agent's stream operations.
func DockerStreamOperationNames() []string {
	ops := volumeStreamOperations(docker.New("/nonexistent", 0), Options{})
	m := map[string]handler{}
	for n := range ops {
		m[n] = nil
	}
	return sortedNames(m)
}
